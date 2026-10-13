/*
 * rt-gum-sdk stage-2 Daemon.
 *
 * This image is VMA-less mapped into Zygote by the KPM (never via a normal
 * loader): no maps entry, no link_map, no dl_iterate_phdr presence. It links
 * against libc.so for its small bionic surface so the KPM's remote DT_NEEDED registration
 * and import resolution run on the real injection path. Everything else goes
 * through the authenticated daemon syscall (RTGUM_DAEMON_SYSCALL), with the
 * 32-byte session key carried in x2..x5.
 *
 * Exported ABI:
 *   rtgum_stage2_daemon_dispatch(ctx)  - kernel-trampoline entry (INIT/FORK/
 *                                        PACKAGE/RELOAD/SHUTDOWN commands)
 *   rtgum_stage2_daemon_entry()        - legacy probe entry
 *   rtgum_stage2_daemon_ifunc_probe()  - internal IFUNC, repaired by the
 *                                        kernel-generated bootstrap fixup
 *   rtgum_stage2_daemon_ctx[4096]      - kernel-written bootstrap context page
 *   rtgum_stage2_daemon_trampoline[4096] - kernel-generated ARM64 trampoline
 *   rtgum_stage2_daemon_status[8]      - daemon status words
 *   rtgum_stage2_daemon_descriptor     - compatibility descriptor
 */

#include <rtgum/ghost_api.h>
#include <rtgum/gtrace.hpp>
#include <rtgum/gum_api.h>
#include <rtgum/native_backend.hpp>
#include <rtgum/shadow_replace.hpp>
#include <rtgum/symbol_resolver.hpp>

#include <art_hook/mako_host.h>
#include <jni.h>
#include <pthread.h>

namespace {

unsigned long g_session_words[4];
unsigned long g_status_va = 0;
unsigned long g_ctx_va = 0;
unsigned long g_module_base = 0;
unsigned long g_module_size = 0;
unsigned long g_module_unload_entry = 0;
volatile unsigned int g_module_unloading = 0;
bool g_api_ready = false;
GhostApi g_api{};
HostApiV2 g_host_api{};
rtgum::native::Engine g_engine{};
rtgum::shadow::Engine g_shadow_engine{};
rtgum::symbols::Resolver g_symbol_resolver{};
long g_java_state = 0; /* 0 idle, 1 bound, negative last error */
long g_lua_state = 0;  /* 0 idle, 1 bound, negative last error */
/* Mako ART hook backend: lazily linked from the KPM cache on the first
 * artHook call. g_mako_path comes from the PACKAGE dispatch payload (the
 * Manager switch pushed it into the KPM cache). */
char g_mako_path[160];
bool g_mako_enabled = false;
long g_mako_state = 0; /* 0 idle, 1 bound, negative last error */
unsigned long g_mako_base = 0;
MakoHostApi g_mako_host{};
MakoHookApi g_mako_hooks{};
MakoReflectionCache g_mako_reflection{};
bool g_mako_reflection_ready = false;
constexpr unsigned int kMakoHandleCapacity = 64U;
unsigned long g_mako_handles[kMakoHandleCapacity]{};
/* Gum backend: lazily ghost-linked from the KPM cache on the first Gum
 * call. g_gum_path comes from the PACKAGE dispatch payload's fourth
 * segment. */
char g_gum_path[160];
long g_gum_state = 0; /* 0 idle, 1 bound, negative last error */
unsigned long g_gum_base = 0;
unsigned long g_gum_size = 0;
RtGumHost g_gum_host{};
RtGumApi g_gum_api{};
/* Lua helper: ghost-linked from the KPM cache (third-party apps cannot
 * dlopen /data/local/tmp or another app's code_cache). */
char g_lua_path[160];
unsigned long g_lua_base = 0;
unsigned long g_lua_size = 0;

/* Daemon-owned in-memory DEX runtime. The Java helper may still provide the
 * ART hook and Binder backends, but it is deliberately not involved here:
 * DEX loading must keep working when the ART switch and helper SO are absent.
 *
 * A slot owns the independent ghost copy, the loader/buffer global refs and
 * every jclass returned to a module. Handles include a generation so a stale
 * module cannot address a newly reused slot. */
constexpr unsigned int kDexSlotCapacity = 8U;
constexpr unsigned int kDexClassCapacity = 32U;
constexpr unsigned long kDexMaximumBytes = 16UL * 1024UL * 1024UL;
constexpr unsigned long kDexPageSize = 4096UL;

struct DexJniCache final {
    JavaVM *vm;
    jmethodID in_memory_loader_constructor;
    jmethodID class_loader_load_class;
    jmethodID thread_current;
    jmethodID thread_get_context_loader;
    jmethodID activity_thread_current_application;
    jmethodID context_get_class_loader;
    bool activity_thread_available;
    bool context_available;
    bool ready;
};

struct DexSlot final {
    unsigned long handle;
    unsigned long last_unloaded_handle;
    unsigned long ghost_address;
    unsigned long ghost_span_size;
    unsigned long source_size;
    unsigned long owner_pid;
    jobject loader;
    jobject buffer;
    jobject classes[kDexClassCapacity];
    unsigned int class_count;
    bool active;
};

DexJniCache g_dex_jni{};
DexSlot g_dex_slots[kDexSlotCapacity]{};
jobject g_dex_app_loader = nullptr;
volatile unsigned int g_dex_lock = 0U;
unsigned int g_dex_generation = 1U;
bool g_dex_process_ready = false;

/* Binder and linker interception live in the Daemon itself.  The base hooks
 * are installed lazily through code Shadow Pages; only rule callbacks point
 * into the active .ghm and those are drained before that image is unmapped. */
constexpr unsigned int kInterceptorRuleCapacity = 16U;
constexpr unsigned int kInterceptorThreadCapacity = 32U;
constexpr unsigned int kJniOnLoadHookCapacity = 8U;
constexpr unsigned long kInterceptorTextCapacity = 96UL;
constexpr unsigned long kBinderRuleTag = 0x4942000000000000UL; /* "IB" */
constexpr unsigned long kLinkerRuleTag = 0x494c000000000000UL; /* "IL" */
constexpr unsigned long kLifecycleRuleTag = 0x4953000000000000UL; /* "IS" */
constexpr unsigned long kJniTraceRuleTag = 0x494a000000000000UL; /* "IJ" */

struct BinderRule final {
    unsigned long handle;
    unsigned long retired_handle;
    RtGumBinderInterceptor before;
    RtGumBinderInterceptor after;
    void *user_data;
    unsigned int match_flags;
    unsigned int in_flight;
    bool active;
    char token[kInterceptorTextCapacity];
};

struct LinkerRule final {
    unsigned long handle;
    unsigned long retired_handle;
    RtGumLinkerInterceptor before;
    RtGumLinkerInterceptor after;
    void *user_data;
    unsigned int match_flags;
    unsigned int in_flight;
    bool active;
    char name[kInterceptorTextCapacity];
};

struct LifecycleRule final {
    unsigned long handle;
    unsigned long retired_handle;
    RtGumSoLifecycleCallback callback;
    void *user_data;
    unsigned int match_flags;
    unsigned int event_mask;
    unsigned int in_flight;
    bool active;
    char name[kInterceptorTextCapacity];
};

struct JniTraceRule final {
    unsigned long handle;
    unsigned long retired_handle;
    RtGumJniTraceCallback callback;
    void *user_data;
    unsigned int match_flags;
    unsigned int in_flight;
    bool active;
    char class_name[kInterceptorTextCapacity];
    char method_name[kInterceptorTextCapacity];
    char signature[kInterceptorTextCapacity];
};

struct JniOnLoadHook final {
    unsigned long target;
    unsigned long original;
    unsigned long hook_handle;
    unsigned int wrappers;
    bool active;
    bool retiring;
    char name[kInterceptorTextCapacity];
};

struct InterceptorThread final {
    long tid;
    unsigned int binder_depth;
    unsigned int linker_depth;
    unsigned int jni_depth;
};

using BinderNative = jboolean (*)(JNIEnv *, jobject, jint, jobject, jobject, jint);
using LinkerDlopen = void *(*)(const char *, int, const void *, const void *);
using SoinfoCallConstructors = void (*)(void *);
using SoinfoGetRealpath = const char *(*)(const void *);
using JniOnLoad = jint (*)(JavaVM *, void *);
using RegisterNatives = jint (*)(JNIEnv *, jclass, const JNINativeMethod *, jint);
using ParcelForJavaObject = void *(*)(JNIEnv *, jobject);
using ParcelData = const unsigned char *(*)(const void *);
using ParcelDataSize = unsigned long (*)(const void *);
using String16Ctor = void (*)(void *, const char16_t *, unsigned long);
using String16Dtor = void (*)(void *);
using String8From16Ctor = void (*)(void *, const void *);
using String8Dtor = void (*)(void *);
using String8Length = unsigned long (*)(const void *);

struct ParcelBridge final {
    ParcelForJavaObject parcel_for_java;
    ParcelData data;
    ParcelDataSize data_size;
    String16Ctor string16_ctor;
    String16Dtor string16_dtor;
    String8From16Ctor string8_ctor;
    String8Dtor string8_dtor;
    String8Length string8_length;
    bool ready;
};

struct InterceptorRuntime final {
    BinderRule binder_rules[kInterceptorRuleCapacity];
    LinkerRule linker_rules[kInterceptorRuleCapacity];
    LifecycleRule lifecycle_rules[kInterceptorRuleCapacity];
    JniTraceRule jni_rules[kInterceptorRuleCapacity];
    JniOnLoadHook jni_onload_hooks[kJniOnLoadHookCapacity];
    InterceptorThread threads[kInterceptorThreadCapacity];
    ParcelBridge parcel;
    unsigned long binder_original;
    unsigned long linker_original;
    unsigned long constructors_original;
    unsigned long constructors_target;
    unsigned long register_natives_original;
    SoinfoGetRealpath soinfo_get_realpath;
    jmethodID class_get_name;
    unsigned long binder_hook_handle;
    unsigned long linker_hook_handle;
    unsigned long constructors_hook_handle;
    unsigned long register_natives_hook_handle;
    unsigned long binder_calls;
    unsigned long binder_matched;
    unsigned long binder_callback_errors;
    unsigned long linker_calls;
    unsigned long linker_matched;
    unsigned long linker_callback_errors;
    unsigned long lifecycle_calls;
    unsigned long lifecycle_matched;
    unsigned long lifecycle_callback_errors;
    unsigned long jni_calls;
    unsigned long jni_matched;
    unsigned long jni_callback_errors;
    /* Published as pid|kInterceptorOwnerRebasing while a freshly forked
     * process clears lock and in-flight state inherited from vanished parent
     * threads.  Hook/rule/trampoline state itself remains private and live. */
    unsigned long owner_pid;
    unsigned int binder_generation;
    unsigned int linker_generation;
    unsigned int lifecycle_generation;
    unsigned int jni_generation;
    unsigned int lock;
    unsigned int binder_wrappers;
    unsigned int linker_wrappers;
    unsigned int constructors_wrappers;
    unsigned int register_natives_wrappers;
    bool binder_ready;
    bool binder_starting;
    bool binder_stopping;
    bool linker_ready;
    bool linker_starting;
    bool linker_stopping;
    bool constructors_ready;
    bool constructors_starting;
    bool constructors_stopping;
    bool register_natives_ready;
    bool register_natives_starting;
    bool register_natives_stopping;
    bool binder_logging;
};

InterceptorRuntime g_interceptors{};

/* Generic ghost-image loader shared by user modules and the mako backend. */
long load_ghost_image(const char *path,
                      const char *export_name,
                      unsigned long *out_base,
                      unsigned long *out_entry,
                      unsigned long *out_size);
long api_module_unload(unsigned long base);
long resolver_cache_alloc(unsigned long size, unsigned long *out_address);
long resolver_cache_free(unsigned long address);
long api_log(const char *text);
long api_status(unsigned int index, unsigned long value);
long api_ghost_alloc(unsigned long size, unsigned int protection,
                     unsigned long *out_address);
long api_ghost_protect(unsigned long address, unsigned int protection);
long api_ghost_free(unsigned long address);
long api_ghost_alloc_span(unsigned long size,
                          unsigned int protection,
                          unsigned long *out_address,
                          unsigned long *out_span_size);
long api_ghost_alloc_near_span(unsigned long size,
                               unsigned long alignment,
                               unsigned int protection,
                               unsigned long near_address,
                               unsigned long max_distance,
                               unsigned long *out_address,
                               unsigned long *out_span_size);
long api_ghost_fork_policy(unsigned long address, unsigned long span_size,
                           bool propagate);
long api_module_fork_policy(unsigned long base, bool propagate);
long api_ghost_free_span(unsigned long address, unsigned long span_size);
long release_all_dex_loaders();
long release_dex_process_state();
long release_module_interceptors();
long release_interceptor_process_state();
long interceptor_revert_base(unsigned long handle);

/* Deferred module entry: the PACKAGE dispatch hijacks the app's main thread
 * during its critical startup window. Ghost-loading large backends (Gum is
 * ~11MB with 200+ imports) would blow the ActivityManager attach timeout, so
 * the module entry runs on a fresh thread instead. */
struct DeferredModuleJob {
    GhostApi *api;
    unsigned long status_va;
    GhostEntry entry;
    unsigned long phase;
};

DeferredModuleJob g_module_job{};

void deferred_module_entry(void *argument)
{
    auto *job = static_cast<DeferredModuleJob *>(argument);
    if (!job || !job->entry) return;
    job->entry(job->api);
    job->api->status(RTGUM_DAEMON_STATUS_MODULES, 1);
    job->api->status(RTGUM_DAEMON_STATUS_PHASE, job->phase);
    job->api->log("rtgum-stage2-daemon: module loaded (deferred)");
}

struct CloneJob {
    /* 0 free, 1 being initialized, 2 published/running. Unload treats state 1
     * conservatively so it cannot race a producer that has claimed the slot
     * but has not published its function pointer yet. */
    volatile unsigned int claimed;
    void (*function)(void *);
    void *argument;
};

constexpr unsigned int kCloneJobCapacity = 8U;
CloneJob g_clone_jobs[kCloneJobCapacity]{};

void *run_clone_job(void *opaque)
{
    auto *job = static_cast<CloneJob *>(opaque);
    if (!job) return nullptr;
    void (*function)(void *) = job->function;
    void *argument = job->argument;
    if (function) function(argument);
    job->function = nullptr;
    job->argument = nullptr;
    __atomic_store_n(&job->claimed, 0U, __ATOMIC_RELEASE);
    return nullptr;
}

bool address_in_active_module(const void *address)
{
    const unsigned long value = reinterpret_cast<unsigned long>(address);
    return g_module_base != 0 && g_module_size != 0 && value >= g_module_base &&
           value - g_module_base < g_module_size;
}

bool active_module_job_running()
{
    for (unsigned int index = 0; index < kCloneJobCapacity; ++index) {
        const unsigned int state =
            __atomic_load_n(&g_clone_jobs[index].claimed, __ATOMIC_ACQUIRE);
        if (state == 1U) return true;
        if (state == 2U && address_in_active_module(
                               reinterpret_cast<const void *>(
                                   g_clone_jobs[index].function)))
            return true;
    }
    return false;
}

extern "C" void *memset(void *destination, int value, unsigned long length);

unsigned long load_u64(const void *address)
{
    return *reinterpret_cast<const volatile unsigned long *>(address);
}

unsigned long ghost_length(const char *text, unsigned long limit)
{
    unsigned long length = 0;
    if (!text) return 0;
    while (length < limit && text[length] != '\0') ++length;
    return length;
}

bool ghost_starts_with(const char *text, const char *prefix)
{
    if (!text || !prefix) return false;
    while (*prefix != '\0') {
        if (*text++ != *prefix++) return false;
    }
    return true;
}

static inline long daemon_syscall(long op, unsigned long argument)
{
    register long x0 asm("x0") = op;
    register unsigned long x1 asm("x1") = argument;
    register unsigned long x2 asm("x2") = g_session_words[0];
    register unsigned long x3 asm("x3") = g_session_words[1];
    register unsigned long x4 asm("x4") = g_session_words[2];
    register unsigned long x5 asm("x5") = g_session_words[3];
    register long x8 asm("x8") = RTGUM_DAEMON_SYSCALL;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                 : "memory");
    return x0;
}

/* Ordinary user-mode syscalls (openat/read/close): the Daemon reads its own
 * /proc files itself, so the KPM never needs cross-process /proc access. */
static inline long user_syscall(long number,
                                long argument0,
                                long argument1,
                                long argument2)
{
    register long x8 asm("x8") = number;
    register long x0 asm("x0") = argument0;
    register long x1 asm("x1") = argument1;
    register long x2 asm("x2") = argument2;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x8)
                 : "memory");
    return x0;
}

static inline long user_syscall6(long number,
                                 long argument0,
                                 long argument1,
                                 long argument2,
                                 long argument3,
                                 long argument4,
                                 long argument5)
{
    register long x8 asm("x8") = number;
    register long x0 asm("x0") = argument0;
    register long x1 asm("x1") = argument1;
    register long x2 asm("x2") = argument2;
    register long x3 asm("x3") = argument3;
    register long x4 asm("x4") = argument4;
    register long x5 asm("x5") = argument5;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                 : "memory");
    return x0;
}

long host_open_read(const char *path)
{
    return user_syscall(56, -100, reinterpret_cast<long>(path), 0x80000);
}

long host_read(long fd, void *buffer, unsigned long size)
{
    return user_syscall(63, fd, reinterpret_cast<long>(buffer), static_cast<long>(size));
}

long host_seek(long fd, long offset, int whence)
{
    return user_syscall(62, fd, offset, static_cast<long>(whence));
}

long host_close(long fd)
{
    return user_syscall(57, fd, 0, 0);
}

long host_mmap(unsigned long size, unsigned long protection)
{
    return user_syscall6(222,
                         0,
                         static_cast<long>(size),
                         static_cast<long>(protection),
                         static_cast<long>(rtgum::native::kMapPrivate | rtgum::native::kMapAnonymous),
                         -1,
                         0);
}

long resolver_map_rw(unsigned long size)
{
    return host_mmap(size, rtgum::native::kProtRead | rtgum::native::kProtWrite);
}

long host_mprotect(unsigned long address, unsigned long size, unsigned long protection)
{
    return user_syscall(226,
                        static_cast<long>(address),
                        static_cast<long>(size),
                        static_cast<long>(protection));
}

long host_munmap(unsigned long address, unsigned long size)
{
    return user_syscall(215, static_cast<long>(address), static_cast<long>(size), 0);
}

void host_clear_cache(unsigned long address, unsigned long size)
{
    const unsigned long end = address + size;
    for (unsigned long line = address & ~63UL; line < end; line += 64UL) {
        asm volatile("dc cvau, %0" ::"r"(line) : "memory");
    }
    asm volatile("dsb ish" ::: "memory");
    for (unsigned long line = address & ~63UL; line < end; line += 64UL) {
        asm volatile("ic ivau, %0" ::"r"(line) : "memory");
    }
    asm volatile("dsb ish; isb" ::: "memory");
}

long host_clone(void (*function)(void *), void *argument)
{
    if (!function) return RTGUM_HOST_ERR_INVAL;
    if (__atomic_load_n(&g_module_unloading, __ATOMIC_ACQUIRE) != 0U &&
        address_in_active_module(reinterpret_cast<const void *>(function)))
        return RTGUM_HOST_ERR_BUSY;
    CloneJob *job = nullptr;
    for (unsigned int index = 0; index < kCloneJobCapacity; ++index) {
        unsigned int expected = 0U;
        if (__atomic_compare_exchange_n(&g_clone_jobs[index].claimed, &expected,
                                        1U, false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE)) {
            job = &g_clone_jobs[index];
            break;
        }
    }
    if (!job) return RTGUM_HOST_ERR_BUSY;
    job->function = function;
    job->argument = argument;
    if (__atomic_load_n(&g_module_unloading, __ATOMIC_ACQUIRE) != 0U &&
        address_in_active_module(reinterpret_cast<const void *>(function))) {
        job->function = nullptr;
        job->argument = nullptr;
        __atomic_store_n(&job->claimed, 0U, __ATOMIC_RELEASE);
        return RTGUM_HOST_ERR_BUSY;
    }
    __atomic_store_n(&job->claimed, 2U, __ATOMIC_RELEASE);

    /* raw clone(2) shares the caller's TLS pointer and does not create a valid
     * bionic/ART thread. GetEnv can then read the parent's JNI slot, while the
     * first stack-sensitive JNI call crashes in ART's StackVisitor. */
    pthread_t thread{};
    const int created = pthread_create(&thread, nullptr, run_clone_job, job);
    if (created != 0) {
        job->function = nullptr;
        job->argument = nullptr;
        __atomic_store_n(&job->claimed, 0U, __ATOMIC_RELEASE);
        return -created;
    }
    (void)pthread_detach(thread);
    return 0;
}

long host_sleep_ms(unsigned int milliseconds)
{
    long spec[2];
    spec[0] = static_cast<long>(milliseconds / 1000U);
    spec[1] = static_cast<long>(milliseconds % 1000U) * 1000000L;
    return user_syscall(101, reinterpret_cast<long>(spec), 0, 0);
}

long resolver_vma_snapshot(rtgum::symbols::VmaRange *ranges,
                           unsigned int capacity,
                           unsigned int *out_count)
{
    if (!ranges || !out_count || capacity == 0U) return RTGUM_HOST_ERR_INVAL;
    *out_count = 0;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) =
        reinterpret_cast<unsigned long>(ranges);
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) =
        capacity;
    const long count = daemon_syscall(RTGUM_DAEMON_OP_VMA_SNAPSHOT, 0);
    if (count < 0) return count;
    if (static_cast<unsigned long>(count) > capacity) return RTGUM_HOST_ERR_NOMEM;
    *out_count = static_cast<unsigned int>(count);
    return 0;
}

long resolver_memory_read(unsigned long address, void *buffer, unsigned long length)
{
    if (address == 0 || !buffer || length == 0 || length > 4096UL)
        return RTGUM_HOST_ERR_INVAL;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) = address;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) =
        reinterpret_cast<unsigned long>(buffer);
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 16UL) =
        length;
    return daemon_syscall(RTGUM_DAEMON_OP_MEMORY_READ, 0);
}

long resolver_memory_write(unsigned long address, const void *buffer,
                           unsigned long length)
{
    if (address == 0UL || buffer == nullptr || length == 0UL ||
        length > 4096UL || address + length < address)
        return RTGUM_HOST_ERR_INVAL;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) =
        address;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) =
        reinterpret_cast<unsigned long>(buffer);
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 16UL) =
        length;
    return daemon_syscall(RTGUM_DAEMON_OP_MEMORY_WRITE, 0);
}

long shadow_kernel_patch(unsigned long address, const unsigned char *bytes,
                         unsigned long length, bool fork_propagate)
{
    if (address == 0UL || !bytes || length == 0UL || length > 32UL)
        return RTGUM_HOST_ERR_INVAL;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) =
        address;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) =
        length;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 16UL) =
        fork_propagate ? 1UL : 0UL;
    auto *destination = reinterpret_cast<volatile unsigned char *>(
        g_ctx_va + RTGUM_CTX_PAYLOAD + 24UL);
    for (unsigned long index = 0UL; index < length; ++index)
        destination[index] = bytes[index];
    return daemon_syscall(RTGUM_DAEMON_OP_SHADOW_CODE_PATCH, 0);
}

long shadow_kernel_unpatch(unsigned long address, unsigned long length)
{
    if (address == 0UL || length == 0UL || length > 32UL)
        return RTGUM_HOST_ERR_INVAL;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) =
        address;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) =
        length;
    return daemon_syscall(RTGUM_DAEMON_OP_SHADOW_CODE_UNPATCH, 0);
}

long shadow_kernel_query(unsigned long address, unsigned long length)
{
    if (address == 0UL || length == 0UL || length > 32UL)
        return RTGUM_HOST_ERR_INVAL;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) =
        address;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) =
        length;
    return daemon_syscall(RTGUM_DAEMON_OP_SHADOW_CODE_QUERY, 0);
}

long resolver_ghost_file_size(unsigned long base, unsigned long *out_size)
{
    if (base == 0 || !out_size) return RTGUM_HOST_ERR_INVAL;
    *out_size = 0;
    const long size = daemon_syscall(RTGUM_DAEMON_OP_MODULE_FILE_SIZE, base);
    if (size <= 0) return size < 0 ? size : RTGUM_HOST_ERR_NOENT;
    *out_size = static_cast<unsigned long>(size);
    return 0;
}

long resolver_ghost_file_copy(unsigned long base,
                              void *buffer,
                              unsigned long length)
{
    if (base == 0 || !buffer || length == 0) return RTGUM_HOST_ERR_INVAL;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) = base;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) =
        reinterpret_cast<unsigned long>(buffer);
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 16UL) =
        length;
    return daemon_syscall(RTGUM_DAEMON_OP_MODULE_FILE_COPY, 0);
}

long resolver_find_export(const char *soname,
                          const char *symbol,
                          unsigned long *out_address)
{
    const long status = g_symbol_resolver.FindExport(soname, symbol, out_address);
    if (status != 0) {
        char debug[220];
        g_symbol_resolver.DebugImages(debug, sizeof(debug));
        api_log(debug);
    }
    return status;
}

long host_symbolize_pc(unsigned long pc, char *out, unsigned long capacity)
{
    return g_symbol_resolver.Format(pc, out, capacity);
}

long host_symbolize_batch(const unsigned long *pcs,
                          unsigned long count,
                          char *out,
                          unsigned long capacity)
{
    return g_symbol_resolver.FormatBatch(pcs, count, out, capacity);
}

long host_find_export(const char *soname, const char *symbol, unsigned long *out_address)
{
    return g_engine.FindExport(soname, symbol, out_address);
}

long host_replace(unsigned long target,
                  unsigned long replacement,
                  unsigned long *out_original,
                  unsigned long *out_handle)
{
    return g_engine.Replace(target, replacement, out_original, out_handle);
}

long host_shadow_replace(unsigned long target,
                         unsigned long replacement,
                         unsigned long *out_original,
                         unsigned long *out_handle)
{
    return g_shadow_engine.Replace(target, replacement, true, out_original,
                                   out_handle);
}

long host_hook_symbol(const char *soname,
                      const char *symbol,
                      unsigned long replacement,
                      unsigned long *out_original,
                      unsigned long *out_handle)
{
    return g_engine.HookSymbol(soname, symbol, replacement, out_original, out_handle);
}

long host_wait_export(const char *soname,
                      const char *symbol,
                      unsigned int timeout_ms,
                      unsigned long *out_address)
{
    return g_engine.WaitExport(soname, symbol, timeout_ms, out_address);
}

long host_gtrace_decode(const unsigned char *code,
                        unsigned long size,
                        unsigned long pc,
                        char *out,
                        unsigned long capacity)
{
    return rtgum::native::GtraceDecode(code, size, pc, out, capacity);
}

long host_gtrace_format_path(const RtGumGtraceStep *steps,
                             unsigned long count,
                             unsigned long image_start,
                             unsigned long image_end,
                             char *out,
                             unsigned long capacity)
{
    return rtgum::native::GtraceFormatPath(
        steps, count, image_start, image_end, out, capacity);
}

long host_load_dex(const unsigned char *bytes,
                   unsigned long size,
                   unsigned int use_app_parent,
                   unsigned long *out_handle);
long host_find_class_from_dex(unsigned long handle,
                              const char *jni_class,
                              unsigned long *out_class);
long host_unload_dex(unsigned long handle);
long host_hook_binder(unsigned long *out_handle);
long host_lua_eval(const char *script, char *error, unsigned long error_capacity);
long host_lua_eval_async(const char *script, char *error,
                         unsigned long error_capacity);
long host_lua_stop();

long host_revert(unsigned long handle)
{
    if (g_shadow_engine.Owns(handle)) {
        const long special = interceptor_revert_base(handle);
        if (special != RTGUM_HOST_ERR_NOENT) return special;
        return g_shadow_engine.Revert(handle);
    }
    return g_engine.Revert(handle);
}

long host_query(unsigned long handle, unsigned int *out_backend, unsigned int *out_state)
{
    if (g_shadow_engine.Owns(handle)) {
        if (!out_backend || !out_state) return RTGUM_HOST_ERR_INVAL;
        *out_backend = RTGUM_HOST_BACKEND_NATIVE;
        return g_shadow_engine.Query(handle, out_state);
    }
    return g_engine.Query(handle, out_backend, out_state);
}

long host_defer(void (*function)(void *), void *argument)
{
    return g_engine.Defer(function, argument);
}

using GetCreatedJavaVMs = jint (*)(JavaVM **, jsize, jsize *);

bool prepare_mako_reflection_cache()
{
    if (g_mako_reflection_ready) return true;
    unsigned long address = 0;
    if (host_find_export("libart.so", "JNI_GetCreatedJavaVMs", &address) != 0 ||
        address == 0)
        return false;
    JavaVM *vm = nullptr;
    jsize count = 0;
    auto get_created = reinterpret_cast<GetCreatedJavaVMs>(address);
    if (get_created(&vm, 1, &count) != JNI_OK || vm == nullptr || count == 0)
        return false;
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK ||
        env == nullptr)
        return false;

    jclass object_class = env->FindClass("java/lang/Object");
    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jclass class_class = env->FindClass("java/lang/Class");
    if (env->ExceptionCheck() || object_class == nullptr || method_class == nullptr ||
        class_class == nullptr) {
        env->ExceptionClear();
        if (object_class != nullptr) env->DeleteLocalRef(object_class);
        if (method_class != nullptr) env->DeleteLocalRef(method_class);
        if (class_class != nullptr) env->DeleteLocalRef(class_class);
        return false;
    }

    const jmethodID hash_code =
        env->GetMethodID(object_class, "hashCode", "()I");
    const jmethodID return_type = env->GetMethodID(
        method_class, "getReturnType", "()Ljava/lang/Class;");
    const jmethodID parameter_types = env->GetMethodID(
        method_class, "getParameterTypes", "()[Ljava/lang/Class;");
    const jmethodID class_name = env->GetMethodID(
        class_class, "getName", "()Ljava/lang/String;");
    const bool complete = !env->ExceptionCheck() && hash_code != nullptr &&
                          return_type != nullptr && parameter_types != nullptr &&
                          class_name != nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(object_class);
    env->DeleteLocalRef(method_class);
    env->DeleteLocalRef(class_class);
    if (!complete) return false;

    MakoReflectionCache candidate{};
    candidate.version = MAKO_REFLECTION_CACHE_VERSION;
    candidate.size = sizeof(candidate);
    candidate.object_hash_code = reinterpret_cast<void *>(hash_code);
    candidate.method_get_return_type = reinterpret_cast<void *>(return_type);
    candidate.method_get_parameter_types = reinterpret_cast<void *>(parameter_types);
    candidate.class_get_name = reinterpret_cast<void *>(class_name);
    g_mako_reflection = candidate;
    __atomic_store_n(&g_mako_reflection_ready, true, __ATOMIC_RELEASE);
    return true;
}

long resolve_named_symbol(const char *soname, const char *symbol, unsigned long *out_address)
{
    if (!out_address) return RTGUM_HOST_ERR_INVAL;
    *out_address = 0;
    return host_find_export(soname, symbol, out_address);
}

long resolve_loader_symbol(const char *symbol, unsigned long *out_address)
{
    if (resolve_named_symbol("libdl.so", symbol, out_address) == 0 && *out_address != 0)
        return 0;
    /* Android's executable linker is mapped from .../bin/linker64, but its
     * DT_SONAME is ld-android.so (API 36 included).  The VMA resolver has no
     * pathname dependency and therefore indexes mapped images by SONAME.
     * Keep the filename spelling as a compatibility fallback for vendor
     * linkers which advertise it directly. */
    if (resolve_named_symbol("ld-android.so", symbol, out_address) == 0 &&
        *out_address != 0)
        return 0;
    if (resolve_named_symbol("linker64", symbol, out_address) == 0 && *out_address != 0)
        return 0;
    return RTGUM_HOST_ERR_NOENT;
}

long host_java_replace(void *env,
                       void *reflected_method,
                       void *hooker_object,
                       void *callback_method,
                       unsigned long *out_handle);
long host_java_revert(unsigned long handle);
long host_java_method(void *env,
                      const char *jni_class,
                      const char *name,
                      const char *signature,
                      unsigned long *out_handle);

long ensure_java_backend()
{
    if (g_java_state == 1) return 0;
    unsigned long dlopen_ext = 0;
    unsigned long loader_dlopen_ext = 0;
    unsigned long dlsym_addr = 0;
    (void)resolve_loader_symbol("android_dlopen_ext", &dlopen_ext);
    (void)resolve_loader_symbol("__loader_android_dlopen_ext", &loader_dlopen_ext);
    (void)resolve_loader_symbol("dlsym", &dlsym_addr);
    if (dlsym_addr == 0) (void)resolve_loader_symbol("__loader_dlsym", &dlsym_addr);
    if ((dlopen_ext == 0 && loader_dlopen_ext == 0) || dlsym_addr == 0) {
        api_log("rtgum-stage2-daemon: java loader symbols missing");
        return RTGUM_HOST_ERR_NOTSUP;
    }

    using DlopenExt = void *(*)(const char *, int, const void *);
    using LoaderDlopenExt = void *(*)(const char *, int, const void *, const void *);
    using DlsymFn = void *(*)(void *, const char *);
    auto *dlopen_fn = reinterpret_cast<DlopenExt>(dlopen_ext);
    auto *loader_fn = reinterpret_cast<LoaderDlopenExt>(loader_dlopen_ext);
    auto *dlsym_fn = reinterpret_cast<DlsymFn>(dlsym_addr);
    const void *caller = reinterpret_cast<const void *>(
        loader_dlopen_ext != 0 ? loader_dlopen_ext : dlopen_ext);

    const char *paths[2] = {RTGUM_JAVA_HELPER_APP_PATH, RTGUM_JAVA_HELPER_STAGING_PATH};
    void *handle = nullptr;
    for (unsigned int index = 0; index < 2U && handle == nullptr; ++index) {
        const char *path = paths[index];
        const long fd = host_open_read(path);
        if (fd < 0) continue;
        alignas(8) unsigned char info[64];
        memset(info, 0, sizeof(info));
        *reinterpret_cast<unsigned long *>(info) = 0x10UL; /* ANDROID_DLEXT_USE_LIBRARY_FD */
        *reinterpret_cast<int *>(info + 28) = static_cast<int>(fd);
        if (loader_fn) {
            handle = loader_fn(RTGUM_JAVA_HELPER_SONAME, 2, info, caller);
            if (!handle) handle = loader_fn(path, 2, nullptr, caller);
        }
        if (!handle && dlopen_fn) {
            handle = dlopen_fn(RTGUM_JAVA_HELPER_SONAME, 2, info);
            if (!handle) handle = dlopen_fn(path, 2, nullptr);
        }
        host_close(fd);
    }
    if (!handle) {
        api_log("rtgum-stage2-daemon: java helper dlopen failed");
        return RTGUM_HOST_ERR_NOENT;
    }
    using BindFn = long (*)(HostApiV2 *);
    auto *bind = reinterpret_cast<BindFn>(dlsym_fn(handle, "rtgum_host_bind_java"));
    if (!bind) {
        api_log("rtgum-stage2-daemon: java helper bind missing");
        return RTGUM_HOST_ERR_NXIO;
    }
    const long bound = bind(&g_host_api);
    if (bound != 0 || g_host_api.hook_java_method == nullptr ||
        g_host_api.hook_java_method == &host_java_method) {
        api_log("rtgum-stage2-daemon: java helper bind failed");
        return bound != 0 ? bound : RTGUM_HOST_ERR_NXIO;
    }
    g_java_state = 1;
    api_log("rtgum-stage2-daemon: java backend bound");
    return 0;
}

long ensure_lua_backend()
{
    if (g_lua_state == 1) return 0;
    if (g_lua_state < 0) return g_lua_state;
    if (g_lua_path[0] == '\0') {
        api_log("rtgum-stage2-daemon: lua path not configured");
        return RTGUM_HOST_ERR_NOENT;
    }
    unsigned long base = 0;
    unsigned long entry_address = 0;
    unsigned long size = 0;
    const long loaded = load_ghost_image(g_lua_path, "rtgum_host_bind_lua",
                                         &base, &entry_address, &size);
    if (loaded != 0 || base == 0 || entry_address == 0 || size == 0) {
        g_lua_state = loaded == RTGUM_HOST_ERR_AGAIN
                          ? 0
                          : (loaded != 0 ? loaded : RTGUM_HOST_ERR_NOENT);
        api_log("rtgum-stage2-daemon: lua ghost load failed");
        return g_lua_state;
    }
    using BindFn = long (*)(HostApiV2 *);
    auto *bind = reinterpret_cast<BindFn>(entry_address);
    const long bound = bind(&g_host_api);
    if (bound != 0 || g_host_api.lua_eval == nullptr ||
        g_host_api.lua_eval == &host_lua_eval) {
        /* A rejected bind must not leave pointers into an image that is about
         * to be removed.  Lua has not accepted work at this point, so this
         * rollback is synchronous and safe. */
        g_host_api.lua_eval = &host_lua_eval;
        g_host_api.lua_eval_async = &host_lua_eval_async;
        g_host_api.lua_stop = &host_lua_stop;
        g_host_api.capabilities &= ~(RTGUM_HOST_CAP_LUA |
                                     RTGUM_HOST_CAP_LUA_ASYNC);
        const long rollback = api_module_unload(base);
        if (rollback != 0)
            api_log("rtgum-stage2-daemon: lua ghost rollback failed");
        api_log("rtgum-stage2-daemon: lua helper bind failed");
        g_lua_state = bound != 0 ? bound : RTGUM_HOST_ERR_NXIO;
        return g_lua_state;
    }
    g_lua_base = base;
    g_lua_size = size;
    g_lua_state = 1;
    api_status(RTGUM_DAEMON_STATUS_LUA_BASE, base);
    if (g_status_va != 0) {
        auto *flags = reinterpret_cast<unsigned long *>(
            g_status_va + RTGUM_DAEMON_STATUS_BACKEND_FLAGS * 8UL);
        __atomic_fetch_or(flags, RTGUM_DAEMON_BACKEND_LUA_GHOST,
                          __ATOMIC_RELEASE);
    }
    api_log("rtgum-stage2-daemon: lua ghost backend bound");
    return 0;
}

/* ============ Daemon-owned in-memory DEX runtime ============ */

struct DexEnv final {
    JNIEnv *env;
    JavaVM *vm;
    bool attached_here;
};

bool dex_lock()
{
    for (unsigned int attempt = 0; attempt < 30000U; ++attempt) {
        unsigned int expected = 0U;
        if (__atomic_compare_exchange_n(&g_dex_lock, &expected, 1U, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return true;
        if ((attempt & 31U) == 31U) (void)host_sleep_ms(1U);
    }
    return false;
}

void dex_unlock()
{
    __atomic_store_n(&g_dex_lock, 0U, __ATOMIC_RELEASE);
}

void dex_clear_exception(JNIEnv *env, const char *stage)
{
    if (!env || !env->ExceptionCheck()) return;
    env->ExceptionClear();
    api_log(stage);
}

long dex_attach(DexEnv &attached)
{
    attached = {};
    JavaVM *vm = g_dex_jni.vm;
    if (!vm) {
        unsigned long address = 0;
        if (host_find_export("libart.so", "JNI_GetCreatedJavaVMs", &address) != 0 ||
            address == 0)
            return RTGUM_HOST_ERR_NOENT;
        JavaVM *found = nullptr;
        jsize count = 0;
        auto get_created = reinterpret_cast<GetCreatedJavaVMs>(address);
        if (get_created(&found, 1, &count) != JNI_OK || !found || count == 0)
            return RTGUM_HOST_ERR_NXIO;
        vm = found;
        g_dex_jni.vm = vm;
    }

    JNIEnv *env = nullptr;
    const jint state = vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (state == JNI_OK && env) {
        attached.env = env;
        attached.vm = vm;
        return 0;
    }
    if (state != JNI_EDETACHED || vm->AttachCurrentThread(&env, nullptr) != JNI_OK ||
        !env)
        return RTGUM_HOST_ERR_NXIO;
    attached.env = env;
    attached.vm = vm;
    attached.attached_here = true;
    return 0;
}

void dex_detach(DexEnv &attached)
{
    if (attached.attached_here && attached.vm)
        (void)attached.vm->DetachCurrentThread();
    attached = {};
}

bool prepare_dex_jni_cache_locked(JNIEnv *env)
{
    if (g_dex_jni.ready) return true;
    if (!env) return false;

    DexJniCache candidate{};
    candidate.vm = g_dex_jni.vm;
    jclass in_memory = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jclass class_loader = env->FindClass("java/lang/ClassLoader");
    jclass thread = env->FindClass("java/lang/Thread");
    if (env->ExceptionCheck() || !in_memory || !class_loader || !thread) {
        dex_clear_exception(env, "rtgum-dex: bootstrap class lookup failed");
        if (in_memory) env->DeleteLocalRef(in_memory);
        if (class_loader) env->DeleteLocalRef(class_loader);
        if (thread) env->DeleteLocalRef(thread);
        return false;
    }

    candidate.in_memory_loader_constructor = env->GetMethodID(
        in_memory, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    candidate.class_loader_load_class = env->GetMethodID(
        class_loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    candidate.thread_current = env->GetStaticMethodID(
        thread, "currentThread", "()Ljava/lang/Thread;");
    candidate.thread_get_context_loader = env->GetMethodID(
        thread, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    if (env->ExceptionCheck() || !candidate.in_memory_loader_constructor ||
        !candidate.class_loader_load_class || !candidate.thread_current ||
        !candidate.thread_get_context_loader) {
        dex_clear_exception(env, "rtgum-dex: bootstrap method lookup failed");
        env->DeleteLocalRef(in_memory);
        env->DeleteLocalRef(class_loader);
        env->DeleteLocalRef(thread);
        return false;
    }

    /* ActivityThread is an optional early-app path. The public Thread context
     * ClassLoader path remains the fallback, so hidden API changes cannot make
     * isolated DEX loading fail. */
    jclass activity_thread = env->FindClass("android/app/ActivityThread");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        activity_thread = nullptr;
    }
    jclass context = env->FindClass("android/content/Context");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        context = nullptr;
    }
    if (activity_thread) {
        candidate.activity_thread_current_application = env->GetStaticMethodID(
            activity_thread, "currentApplication", "()Landroid/app/Application;");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            candidate.activity_thread_current_application = nullptr;
        }
        candidate.activity_thread_available =
            candidate.activity_thread_current_application != nullptr;
    }
    if (context) {
        candidate.context_get_class_loader = env->GetMethodID(
            context, "getClassLoader", "()Ljava/lang/ClassLoader;");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            candidate.context_get_class_loader = nullptr;
        }
        candidate.context_available = candidate.context_get_class_loader != nullptr;
    }

    env->DeleteLocalRef(in_memory);
    env->DeleteLocalRef(class_loader);
    env->DeleteLocalRef(thread);
    if (activity_thread) env->DeleteLocalRef(activity_thread);
    if (context) env->DeleteLocalRef(context);

    if (env->ExceptionCheck())
        dex_clear_exception(env, "rtgum-dex: optional class lookup failed");
    /* jmethodID values remain valid while their bootstrap/framework classes
     * are loaded. Keep only these IDs across fork: retaining global jclass
     * references in Zygote would leak them when the VMA-less daemon is hot
     * unlinked without a Java-side teardown callback. */
    candidate.ready = true;
    g_dex_jni = candidate;
    return true;
}

bool prepare_dex_jni_cache()
{
    if (g_dex_jni.ready) return true;
    if (!dex_lock()) return false;
    DexEnv attached{};
    const long attach_status = dex_attach(attached);
    const bool ready = attach_status == 0 &&
                       prepare_dex_jni_cache_locked(attached.env);
    dex_detach(attached);
    dex_unlock();
    return ready;
}

long dex_capture_app_loader_locked(JNIEnv *env)
{
    if (g_dex_app_loader) return 0;
    if (!env || !g_dex_jni.ready) return RTGUM_HOST_ERR_NXIO;

    jobject loader = nullptr;
    const bool has_application_path = g_dex_jni.activity_thread_available &&
        g_dex_jni.context_available &&
        g_dex_jni.activity_thread_current_application &&
        g_dex_jni.context_get_class_loader;
    if (has_application_path) {
        jclass activity_thread = env->FindClass("android/app/ActivityThread");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            activity_thread = nullptr;
        }
        jobject application = activity_thread
            ? env->CallStaticObjectMethod(
                  activity_thread,
                  g_dex_jni.activity_thread_current_application)
            : nullptr;
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            application = nullptr;
        }
        if (application) {
            loader = env->CallObjectMethod(application,
                                           g_dex_jni.context_get_class_loader);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                loader = nullptr;
            }
            env->DeleteLocalRef(application);
        }
        if (activity_thread) env->DeleteLocalRef(activity_thread);
    }

    /* When ActivityThread APIs are available, a null application means app
     * binding is genuinely not ready yet. Do not cache the newly attached
     * native thread's bootstrap/system loader as the app parent. */
    if (!loader && !has_application_path) {
        jclass thread_class = env->FindClass("java/lang/Thread");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            thread_class = nullptr;
        }
        jobject thread = thread_class
            ? env->CallStaticObjectMethod(thread_class,
                                          g_dex_jni.thread_current)
            : nullptr;
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            thread = nullptr;
        }
        if (thread) {
            loader = env->CallObjectMethod(thread,
                                           g_dex_jni.thread_get_context_loader);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                loader = nullptr;
            }
            env->DeleteLocalRef(thread);
        }
        if (thread_class) env->DeleteLocalRef(thread_class);
    }
    if (!loader) return RTGUM_HOST_ERR_BUSY;
    jobject global = env->NewGlobalRef(loader);
    env->DeleteLocalRef(loader);
    if (env->ExceptionCheck() || !global) {
        dex_clear_exception(env, "rtgum-dex: app ClassLoader global ref failed");
        return RTGUM_HOST_ERR_NOMEM;
    }
    g_dex_app_loader = global;
    return 0;
}

unsigned int dex_u32(const unsigned char *bytes)
{
    return static_cast<unsigned int>(bytes[0]) |
           (static_cast<unsigned int>(bytes[1]) << 8U) |
           (static_cast<unsigned int>(bytes[2]) << 16U) |
           (static_cast<unsigned int>(bytes[3]) << 24U);
}

bool valid_dex_image(const unsigned char *bytes, unsigned long size)
{
    if (!bytes || size < 0x70UL || size > kDexMaximumBytes ||
        size > 0x7fffffffUL)
        return false;
    if (bytes[0] != 'd' || bytes[1] != 'e' || bytes[2] != 'x' ||
        bytes[3] != '\n' || bytes[4] < '0' || bytes[4] > '9' ||
        bytes[5] < '0' || bytes[5] > '9' || bytes[6] < '0' ||
        bytes[6] > '9' || bytes[7] != 0)
        return false;
    return dex_u32(bytes + 32U) == size &&
           dex_u32(bytes + 36U) == 0x70U &&
           dex_u32(bytes + 40U) == 0x12345678U;
}

bool normalize_dex_class_name(const char *input, char *output,
                              unsigned long capacity)
{
    if (!input || !output || capacity < 2UL) return false;
    unsigned long length = ghost_length(input, capacity + 1UL);
    if (length == 0UL || length >= capacity) return false;
    unsigned long begin = 0UL;
    unsigned long end = length;
    if (length >= 2UL && input[0] == 'L' && input[length - 1UL] == ';') {
        begin = 1UL;
        end = length - 1UL;
    }
    if (begin == end) return false;
    unsigned long written = 0UL;
    bool previous_separator = true;
    for (unsigned long index = begin; index < end; ++index) {
        const unsigned char value = static_cast<unsigned char>(input[index]);
        if (value == '[' || value == ';' || value < 0x20U || value == 0x7fU)
            return false;
        const char converted = value == '/' ? '.' : static_cast<char>(value);
        if (converted == '.') {
            if (previous_separator) return false;
            previous_separator = true;
        } else {
            previous_separator = false;
        }
        output[written++] = converted;
    }
    if (previous_separator || written == 0UL) return false;
    output[written] = '\0';
    return true;
}

unsigned long dex_current_pid()
{
    const long pid = user_syscall(172L, 0L, 0L, 0L);
    return pid > 0 ? static_cast<unsigned long>(pid) : 0UL;
}

DexSlot *dex_slot_for_handle(unsigned long handle, unsigned int &slot_index)
{
    const unsigned long encoded = handle & 0xffUL;
    if (encoded == 0UL || encoded > kDexSlotCapacity) return nullptr;
    slot_index = static_cast<unsigned int>(encoded - 1UL);
    DexSlot &slot = g_dex_slots[slot_index];
    return slot.active && slot.handle == handle ? &slot : nullptr;
}

long release_dex_slot_locked(DexSlot &slot, JNIEnv *env)
{
    if (!slot.active || !env) return RTGUM_HOST_ERR_BADF;
    const long freed = api_ghost_free_span(slot.ghost_address,
                                           slot.ghost_span_size);
    if (freed != 0) return freed;
    for (unsigned int index = 0; index < slot.class_count; ++index) {
        if (slot.classes[index]) env->DeleteGlobalRef(slot.classes[index]);
    }
    if (slot.loader) env->DeleteGlobalRef(slot.loader);
    if (slot.buffer) env->DeleteGlobalRef(slot.buffer);
    const unsigned long old_handle = slot.handle;
    slot = {};
    slot.last_unloaded_handle = old_handle;
    return 0;
}

long host_load_dex(const unsigned char *bytes,
                   unsigned long size,
                   unsigned int use_app_parent,
                   unsigned long *out_handle)
{
    if (!out_handle) return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0;
    if (use_app_parent > 1U || !valid_dex_image(bytes, size))
        return RTGUM_HOST_ERR_INVAL;
    if (!g_dex_process_ready) return RTGUM_HOST_ERR_BUSY;
    if (__atomic_load_n(&g_module_unloading, __ATOMIC_ACQUIRE) != 0U)
        return RTGUM_HOST_ERR_BUSY;
    if (!dex_lock()) return RTGUM_HOST_ERR_BUSY;

    long result = 0;
    DexEnv attached{};
    result = dex_attach(attached);
    if (result != 0 || !prepare_dex_jni_cache_locked(attached.env)) {
        if (result == 0) result = RTGUM_HOST_ERR_NOTSUP;
        dex_detach(attached);
        dex_unlock();
        return result;
    }
    if (use_app_parent != 0U) {
        result = dex_capture_app_loader_locked(attached.env);
        if (result != 0) {
            dex_detach(attached);
            dex_unlock();
            return result;
        }
    }

    unsigned int free_index = kDexSlotCapacity;
    for (unsigned int index = 0; index < kDexSlotCapacity; ++index) {
        if (!g_dex_slots[index].active) {
            free_index = index;
            break;
        }
    }
    if (free_index == kDexSlotCapacity) {
        dex_detach(attached);
        dex_unlock();
        return RTGUM_HOST_ERR_BUSY;
    }

    unsigned long ghost_address = 0;
    unsigned long span_size = 0;
    result = api_ghost_alloc_span(size, 3U /* Read | Write */, &ghost_address,
                                  &span_size);
    if (result != 0) {
        dex_detach(attached);
        dex_unlock();
        return result;
    }
    auto *destination = reinterpret_cast<volatile unsigned char *>(ghost_address);
    for (unsigned long index = 0; index < size; ++index)
        destination[index] = bytes[index];

    jobject buffer = attached.env->NewDirectByteBuffer(
        reinterpret_cast<void *>(ghost_address), static_cast<jlong>(size));
    if (attached.env->ExceptionCheck() || !buffer ||
        attached.env->GetDirectBufferAddress(buffer) !=
            reinterpret_cast<void *>(ghost_address) ||
        attached.env->GetDirectBufferCapacity(buffer) != static_cast<jlong>(size)) {
        dex_clear_exception(attached.env, "rtgum-dex: NewDirectByteBuffer failed");
        if (buffer) attached.env->DeleteLocalRef(buffer);
        (void)api_ghost_free_span(ghost_address, span_size);
        dex_detach(attached);
        dex_unlock();
        return RTGUM_HOST_ERR_NOMEM;
    }

    jclass in_memory_loader =
        attached.env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (attached.env->ExceptionCheck() || !in_memory_loader) {
        dex_clear_exception(attached.env,
                            "rtgum-dex: loader class lookup failed");
        if (in_memory_loader) attached.env->DeleteLocalRef(in_memory_loader);
        attached.env->DeleteLocalRef(buffer);
        (void)api_ghost_free_span(ghost_address, span_size);
        dex_detach(attached);
        dex_unlock();
        return RTGUM_HOST_ERR_NOTSUP;
    }
    jobject parent = use_app_parent != 0U ? g_dex_app_loader : nullptr;
    jobject loader = attached.env->NewObject(
        in_memory_loader, g_dex_jni.in_memory_loader_constructor, buffer, parent);
    attached.env->DeleteLocalRef(in_memory_loader);
    if (attached.env->ExceptionCheck() || !loader) {
        dex_clear_exception(attached.env,
                            "rtgum-dex: InMemoryDexClassLoader construction failed");
        if (loader) attached.env->DeleteLocalRef(loader);
        attached.env->DeleteLocalRef(buffer);
        (void)api_ghost_free_span(ghost_address, span_size);
        dex_detach(attached);
        dex_unlock();
        return RTGUM_HOST_ERR_INVAL;
    }

    jobject global_buffer = attached.env->NewGlobalRef(buffer);
    jobject global_loader = attached.env->NewGlobalRef(loader);
    attached.env->DeleteLocalRef(loader);
    attached.env->DeleteLocalRef(buffer);
    if (attached.env->ExceptionCheck() || !global_buffer || !global_loader) {
        dex_clear_exception(attached.env, "rtgum-dex: loader global ref failed");
        if (global_buffer) attached.env->DeleteGlobalRef(global_buffer);
        if (global_loader) attached.env->DeleteGlobalRef(global_loader);
        (void)api_ghost_free_span(ghost_address, span_size);
        dex_detach(attached);
        dex_unlock();
        return RTGUM_HOST_ERR_NOMEM;
    }

    unsigned int generation = g_dex_generation++;
    if (generation == 0U) generation = g_dex_generation++;
    if (g_dex_generation == 0U) g_dex_generation = 1U;
    DexSlot &slot = g_dex_slots[free_index];
    const unsigned long last_unloaded = slot.last_unloaded_handle;
    slot = {};
    slot.last_unloaded_handle = last_unloaded;
    slot.handle = (static_cast<unsigned long>(generation) << 8U) |
                  (static_cast<unsigned long>(free_index) + 1UL);
    slot.ghost_address = ghost_address;
    slot.ghost_span_size = span_size;
    slot.source_size = size;
    slot.owner_pid = dex_current_pid();
    slot.loader = global_loader;
    slot.buffer = global_buffer;
    slot.active = true;
    *out_handle = slot.handle;
    api_log(use_app_parent != 0U ? "rtgum-dex: loaded parent=app"
                                 : "rtgum-dex: loaded parent=bootstrap");
    dex_detach(attached);
    dex_unlock();
    return 0;
}

long host_find_class_from_dex(unsigned long handle,
                              const char *jni_class,
                              unsigned long *out_class)
{
    if (!out_class) return RTGUM_HOST_ERR_INVAL;
    *out_class = 0;
    if (handle == 0UL || !g_dex_process_ready)
        return RTGUM_HOST_ERR_BADF;
    char dotted[512];
    if (!normalize_dex_class_name(jni_class, dotted, sizeof(dotted)))
        return RTGUM_HOST_ERR_INVAL;
    if (!dex_lock()) return RTGUM_HOST_ERR_BUSY;
    unsigned int slot_index = 0;
    DexSlot *slot = dex_slot_for_handle(handle, slot_index);
    if (!slot || slot->owner_pid != dex_current_pid()) {
        dex_unlock();
        return RTGUM_HOST_ERR_BADF;
    }

    DexEnv attached{};
    long result = dex_attach(attached);
    if (result != 0 || !prepare_dex_jni_cache_locked(attached.env)) {
        if (result == 0) result = RTGUM_HOST_ERR_NOTSUP;
        dex_detach(attached);
        dex_unlock();
        return result;
    }
    jstring name = attached.env->NewStringUTF(dotted);
    if (attached.env->ExceptionCheck() || !name) {
        dex_clear_exception(attached.env, "rtgum-dex: class name allocation failed");
        dex_detach(attached);
        dex_unlock();
        return RTGUM_HOST_ERR_NOMEM;
    }
    jobject local_class = attached.env->CallObjectMethod(
        slot->loader, g_dex_jni.class_loader_load_class, name);
    attached.env->DeleteLocalRef(name);
    if (attached.env->ExceptionCheck() || !local_class) {
        dex_clear_exception(attached.env, "rtgum-dex: symbol not found");
        if (local_class) attached.env->DeleteLocalRef(local_class);
        dex_detach(attached);
        dex_unlock();
        return RTGUM_HOST_ERR_NOENT;
    }

    for (unsigned int index = 0; index < slot->class_count; ++index) {
        if (attached.env->IsSameObject(slot->classes[index], local_class)) {
            *out_class = reinterpret_cast<unsigned long>(slot->classes[index]);
            attached.env->DeleteLocalRef(local_class);
            dex_detach(attached);
            dex_unlock();
            return 0;
        }
    }
    if (slot->class_count == kDexClassCapacity) {
        attached.env->DeleteLocalRef(local_class);
        dex_detach(attached);
        dex_unlock();
        return RTGUM_HOST_ERR_BUSY;
    }
    jobject global_class = attached.env->NewGlobalRef(local_class);
    attached.env->DeleteLocalRef(local_class);
    if (attached.env->ExceptionCheck() || !global_class) {
        dex_clear_exception(attached.env, "rtgum-dex: class global ref failed");
        dex_detach(attached);
        dex_unlock();
        return RTGUM_HOST_ERR_NOMEM;
    }
    slot->classes[slot->class_count++] = global_class;
    *out_class = reinterpret_cast<unsigned long>(global_class);
    dex_detach(attached);
    dex_unlock();
    return 0;
}

long host_unload_dex(unsigned long handle)
{
    if (handle == 0UL) return RTGUM_HOST_ERR_BADF;
    if (!dex_lock()) return RTGUM_HOST_ERR_BUSY;
    const unsigned long encoded = handle & 0xffUL;
    if (encoded == 0UL || encoded > kDexSlotCapacity) {
        dex_unlock();
        return RTGUM_HOST_ERR_BADF;
    }
    DexSlot &slot = g_dex_slots[encoded - 1UL];
    if (!slot.active) {
        const long result = slot.last_unloaded_handle == handle
                                ? 0 : RTGUM_HOST_ERR_BADF;
        dex_unlock();
        return result;
    }
    if (slot.handle != handle || slot.owner_pid != dex_current_pid()) {
        dex_unlock();
        return RTGUM_HOST_ERR_BADF;
    }
    DexEnv attached{};
    long result = dex_attach(attached);
    if (result == 0) result = release_dex_slot_locked(slot, attached.env);
    dex_detach(attached);
    dex_unlock();
    if (result == 0) api_log("rtgum-dex: unloaded");
    return result;
}

long release_all_dex_loaders()
{
    if (!dex_lock()) return RTGUM_HOST_ERR_BUSY;
    bool any = false;
    for (unsigned int index = 0; index < kDexSlotCapacity; ++index)
        any = any || g_dex_slots[index].active;
    if (!any) {
        dex_unlock();
        return 0;
    }
    DexEnv attached{};
    long result = dex_attach(attached);
    if (result == 0) {
        for (unsigned int index = 0; index < kDexSlotCapacity; ++index) {
            if (!g_dex_slots[index].active) continue;
            const long released = release_dex_slot_locked(g_dex_slots[index],
                                                           attached.env);
            if (released != 0 && result == 0) result = released;
        }
    }
    dex_detach(attached);
    dex_unlock();
    return result;
}

long release_dex_process_state()
{
    if (!dex_lock()) return RTGUM_HOST_ERR_BUSY;
    g_dex_process_ready = false;
    if (!g_dex_app_loader) {
        dex_unlock();
        return 0;
    }
    DexEnv attached{};
    const long result = dex_attach(attached);
    if (result == 0) {
        attached.env->DeleteGlobalRef(g_dex_app_loader);
        g_dex_app_loader = nullptr;
    }
    dex_detach(attached);
    dex_unlock();
    return result;
}

constexpr unsigned long kInterceptorOwnerRebasing = 1UL << 63U;

void interceptor_prepare_process()
{
    const unsigned long pid = dex_current_pid();
    if (pid == 0UL) return;
    for (;;) {
        unsigned long owner = __atomic_load_n(&g_interceptors.owner_pid,
                                               __ATOMIC_ACQUIRE);
        if (owner == pid) return;
        if ((owner & kInterceptorOwnerRebasing) != 0UL) {
            asm volatile("yield" ::: "memory");
            continue;
        }
        const unsigned long claimed = pid | kInterceptorOwnerRebasing;
        if (!__atomic_compare_exchange_n(&g_interceptors.owner_pid, &owner,
                                         claimed, false, __ATOMIC_ACQ_REL,
                                         __ATOMIC_ACQUIRE))
            continue;

        const bool inherited = owner != 0UL;
        /* Only the forking thread survives into a new process, so lock owner,
         * recursion slots and in-flight counts from other parent threads are
         * stale by definition.  Rules and the installed base hook handles remain
         * valid because their ghost pages and propagating Shadow PTEs were
         * cloned privately by the KPM. */
        __atomic_store_n(&g_interceptors.lock, 0U, __ATOMIC_RELEASE);
        memset(g_interceptors.threads, 0, sizeof(g_interceptors.threads));
        for (BinderRule &rule : g_interceptors.binder_rules)
            rule.in_flight = 0U;
        for (LinkerRule &rule : g_interceptors.linker_rules)
            rule.in_flight = 0U;
        for (LifecycleRule &rule : g_interceptors.lifecycle_rules)
            rule.in_flight = 0U;
        for (JniTraceRule &rule : g_interceptors.jni_rules)
            rule.in_flight = 0U;
        for (JniOnLoadHook &hook : g_interceptors.jni_onload_hooks)
            hook.wrappers = 0U;
        g_interceptors.binder_wrappers = 0U;
        g_interceptors.linker_wrappers = 0U;
        g_interceptors.constructors_wrappers = 0U;
        g_interceptors.register_natives_wrappers = 0U;
        g_interceptors.binder_starting = false;
        g_interceptors.binder_stopping = false;
        g_interceptors.linker_starting = false;
        g_interceptors.linker_stopping = false;
        g_interceptors.constructors_starting = false;
        g_interceptors.constructors_stopping = false;
        g_interceptors.register_natives_starting = false;
        g_interceptors.register_natives_stopping = false;
        if (inherited) {
            g_interceptors.binder_calls = 0UL;
            g_interceptors.binder_matched = 0UL;
            g_interceptors.binder_callback_errors = 0UL;
            g_interceptors.linker_calls = 0UL;
            g_interceptors.linker_matched = 0UL;
            g_interceptors.linker_callback_errors = 0UL;
            g_interceptors.lifecycle_calls = 0UL;
            g_interceptors.lifecycle_matched = 0UL;
            g_interceptors.lifecycle_callback_errors = 0UL;
            g_interceptors.jni_calls = 0UL;
            g_interceptors.jni_matched = 0UL;
            g_interceptors.jni_callback_errors = 0UL;
        }
        __atomic_store_n(&g_interceptors.owner_pid, pid, __ATOMIC_RELEASE);
        return;
    }
}

void interceptor_lock()
{
    interceptor_prepare_process();
    while (__atomic_test_and_set(&g_interceptors.lock, __ATOMIC_ACQUIRE))
        asm volatile("yield" ::: "memory");
}

void interceptor_unlock()
{
    __atomic_clear(&g_interceptors.lock, __ATOMIC_RELEASE);
}

unsigned long bounded_copy(char *destination, unsigned long capacity,
                           const char *source)
{
    if (!destination || capacity == 0UL) return 0UL;
    unsigned long count = 0UL;
    while (source && source[count] != '\0' && count + 1UL < capacity) {
        destination[count] = source[count];
        ++count;
    }
    destination[count] = '\0';
    return count;
}

bool text_equal(const char *left, const char *right)
{
    if (!left || !right) return false;
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

bool text_contains(const char *text, const char *needle)
{
    if (!text || !needle) return false;
    if (*needle == '\0') return true;
    for (const char *start = text; *start != '\0'; ++start) {
        const char *left = start;
        const char *right = needle;
        while (*right != '\0' && *left == *right) {
            ++left;
            ++right;
        }
        if (*right == '\0') return true;
    }
    return false;
}

bool interceptor_match(const char *text, const char *pattern,
                       unsigned int flags, bool exact_default)
{
    if (!text || !pattern) return false;
    if ((flags & RTGUM_INTERCEPT_MATCH_EXACT) != 0U)
        return text_equal(text, pattern);
    if ((flags & RTGUM_INTERCEPT_MATCH_SUBSTRING) != 0U)
        return text_contains(text, pattern);
    return exact_default ? text_equal(text, pattern)
                         : text_contains(text, pattern);
}

bool interceptor_enter_thread(bool binder, bool &nested)
{
    nested = false;
    const long tid = user_syscall(178, 0, 0, 0); /* gettid */
    if (tid <= 0) return false;
    interceptor_lock();
    InterceptorThread *slot = nullptr;
    for (InterceptorThread &candidate : g_interceptors.threads)
        if (candidate.tid == tid) {
            slot = &candidate;
            break;
        }
    if (!slot) {
        for (InterceptorThread &candidate : g_interceptors.threads)
            if (candidate.tid == 0) {
                slot = &candidate;
                slot->tid = tid;
                break;
            }
    }
    if (slot) {
        unsigned int &depth = binder ? slot->binder_depth : slot->linker_depth;
        nested = depth != 0U;
        ++depth;
    }
    interceptor_unlock();
    return slot != nullptr;
}

void interceptor_leave_thread(bool binder)
{
    const long tid = user_syscall(178, 0, 0, 0);
    interceptor_lock();
    for (InterceptorThread &slot : g_interceptors.threads) {
        if (slot.tid != tid) continue;
        unsigned int &depth = binder ? slot.binder_depth : slot.linker_depth;
        if (depth != 0U) --depth;
        if (slot.binder_depth == 0U && slot.linker_depth == 0U &&
            slot.jni_depth == 0U)
            slot.tid = 0;
        break;
    }
    interceptor_unlock();
}

bool interceptor_enter_jni_thread(bool &nested)
{
    nested = false;
    const long tid = user_syscall(178, 0, 0, 0);
    if (tid <= 0) return false;
    interceptor_lock();
    InterceptorThread *slot = nullptr;
    for (InterceptorThread &candidate : g_interceptors.threads)
        if (candidate.tid == tid) {
            slot = &candidate;
            break;
        }
    if (!slot) {
        for (InterceptorThread &candidate : g_interceptors.threads)
            if (candidate.tid == 0) {
                slot = &candidate;
                slot->tid = tid;
                break;
            }
    }
    if (slot) {
        nested = slot->jni_depth != 0U;
        ++slot->jni_depth;
    }
    interceptor_unlock();
    return slot != nullptr;
}

void interceptor_leave_jni_thread()
{
    const long tid = user_syscall(178, 0, 0, 0);
    interceptor_lock();
    for (InterceptorThread &slot : g_interceptors.threads) {
        if (slot.tid != tid) continue;
        if (slot.jni_depth != 0U) --slot.jni_depth;
        if (slot.binder_depth == 0U && slot.linker_depth == 0U &&
            slot.jni_depth == 0U)
            slot.tid = 0;
        break;
    }
    interceptor_unlock();
}

bool token_character(unsigned int value)
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '.' || value == '_' ||
           value == '$' || value == '/' || value == '-';
}

unsigned long parcel_interface_token(JNIEnv *env, jobject data,
                                     char *output, unsigned long capacity)
{
    if (!output || capacity == 0UL) return 0UL;
    output[0] = '\0';
    ParcelBridge &bridge = g_interceptors.parcel;
    if (!bridge.ready || !env || !data) return 0UL;
    void *parcel = bridge.parcel_for_java(env, data);
    if (!parcel) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return 0UL;
    }
    const unsigned char *bytes = bridge.data(parcel);
    unsigned long size = bridge.data_size(parcel);
    if (!bytes || size < 8UL || size > 16UL * 1024UL * 1024UL) return 0UL;
    unsigned long scan = size;
    if (scan > 192UL) scan = 192UL;
    for (unsigned long offset = 0UL; offset + 8UL <= scan; offset += 4UL) {
        const unsigned long count =
            static_cast<unsigned long>(bytes[offset]) |
            (static_cast<unsigned long>(bytes[offset + 1UL]) << 8UL) |
            (static_cast<unsigned long>(bytes[offset + 2UL]) << 16UL) |
            (static_cast<unsigned long>(bytes[offset + 3UL]) << 24UL);
        if (count < 3UL || count > 160UL ||
            count > (size - offset - 4UL) / 2UL ||
            offset + 4UL + (count + 1UL) * 2UL > size)
            continue;
        const auto *characters = reinterpret_cast<const char16_t *>(
            bytes + offset + 4UL);
        bool descriptor = false;
        bool valid = true;
        for (unsigned long index = 0UL; index < count; ++index) {
            const unsigned int value = static_cast<unsigned int>(characters[index]);
            if (!token_character(value)) {
                valid = false;
                break;
            }
            if (value == '.' || value == '/') descriptor = true;
        }
        if (!valid || !descriptor || characters[count] != 0) continue;

        alignas(8) unsigned char string16[32]{};
        alignas(8) unsigned char string8[32]{};
        bridge.string16_ctor(string16, characters, count);
        bridge.string8_ctor(string8, string16);
        const char *utf8 = *reinterpret_cast<const char *const *>(string8);
        unsigned long utf8_length = bridge.string8_length(string8);
        if (!utf8 || utf8_length == 0UL || utf8_length > 512UL) {
            bridge.string8_dtor(string8);
            bridge.string16_dtor(string16);
            continue;
        }
        if (utf8_length + 1UL > capacity) utf8_length = capacity - 1UL;
        for (unsigned long index = 0UL; index < utf8_length; ++index)
            output[index] = utf8[index];
        output[utf8_length] = '\0';
        bridge.string8_dtor(string8);
        bridge.string16_dtor(string16);
        return utf8_length;
    }
    return 0UL;
}

bool resolve_required(const char *soname, const char *symbol,
                      unsigned long &address)
{
    address = 0UL;
    return host_find_export(soname, symbol, &address) == 0 && address != 0UL;
}

long prepare_parcel_bridge()
{
    if (g_interceptors.parcel.ready) return 0;
    ParcelBridge candidate{};
    unsigned long parcel_for_java = 0UL;
    unsigned long parcel_data = 0UL;
    unsigned long parcel_size = 0UL;
    unsigned long string16_ctor = 0UL;
    unsigned long string16_dtor = 0UL;
    unsigned long string8_ctor = 0UL;
    unsigned long string8_dtor = 0UL;
    unsigned long string8_length = 0UL;
    if (!resolve_required("libandroid_runtime.so",
                          "_ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject",
                          parcel_for_java) ||
        !resolve_required("libbinder.so", "_ZNK7android6Parcel4dataEv",
                          parcel_data) ||
        !resolve_required("libbinder.so", "_ZNK7android6Parcel8dataSizeEv",
                          parcel_size) ||
        !resolve_required("libutils.so", "_ZN7android8String16C1EPKDsm",
                          string16_ctor) ||
        !resolve_required("libutils.so", "_ZN7android8String16D1Ev",
                          string16_dtor) ||
        !resolve_required("libutils.so",
                          "_ZN7android7String8C1ERKNS_8String16E",
                          string8_ctor) ||
        !resolve_required("libutils.so", "_ZN7android7String8D1Ev",
                          string8_dtor) ||
        !resolve_required("libutils.so", "_ZNK7android7String86lengthEv",
                          string8_length))
        return RTGUM_HOST_ERR_NOENT;
    candidate.parcel_for_java = reinterpret_cast<ParcelForJavaObject>(parcel_for_java);
    candidate.data = reinterpret_cast<ParcelData>(parcel_data);
    candidate.data_size = reinterpret_cast<ParcelDataSize>(parcel_size);
    candidate.string16_ctor = reinterpret_cast<String16Ctor>(string16_ctor);
    candidate.string16_dtor = reinterpret_cast<String16Dtor>(string16_dtor);
    candidate.string8_ctor = reinterpret_cast<String8From16Ctor>(string8_ctor);
    candidate.string8_dtor = reinterpret_cast<String8Dtor>(string8_dtor);
    candidate.string8_length = reinterpret_cast<String8Length>(string8_length);
    candidate.ready = true;
    g_interceptors.parcel = candidate;
    return 0;
}

long decode_native_art_method(jmethodID method, unsigned long anchor,
                              unsigned long &target)
{
    target = 0UL;
    const unsigned long raw = reinterpret_cast<unsigned long>(method);
    if (raw < 0x10000UL || (raw & 7UL) != 0UL) return RTGUM_HOST_ERR_NOTSUP;
    unsigned long candidates[2] = {raw, 0UL};
    (void)resolver_memory_read(raw, &candidates[1], sizeof(candidates[1]));
    for (unsigned int candidate_index = 0U; candidate_index < 2U;
         ++candidate_index) {
        const unsigned long record = candidates[candidate_index];
        if (record < 0x10000UL || (record & 7UL) != 0UL) continue;
        unsigned long jni_entry = 0UL;
        if (resolver_memory_read(record + 16UL, &jni_entry,
                                 sizeof(jni_entry)) != 0 ||
            jni_entry < 0x10000UL || (jni_entry & 3UL) != 0UL)
            continue;
        const unsigned long distance = jni_entry > anchor ? jni_entry - anchor
                                                          : anchor - jni_entry;
        if (distance > 32UL * 1024UL * 1024UL) continue;
        unsigned int instruction = 0U;
        if (resolver_memory_read(jni_entry, &instruction,
                                 sizeof(instruction)) != 0 || instruction == 0U ||
            instruction == 0xffffffffU)
            continue;
        target = jni_entry;
        return 0;
    }
    return RTGUM_HOST_ERR_NOTSUP;
}

long binder_rule_snapshot(const char *token, unsigned int *indices,
                          RtGumBinderInterceptor *before,
                          RtGumBinderInterceptor *after, void **user_data,
                          unsigned int &count)
{
    count = 0U;
    interceptor_lock();
    for (unsigned int index = 0U; index < kInterceptorRuleCapacity; ++index) {
        BinderRule &rule = g_interceptors.binder_rules[index];
        if (!rule.active ||
            !interceptor_match(token, rule.token, rule.match_flags, true))
            continue;
        ++rule.in_flight;
        indices[count] = index;
        before[count] = rule.before;
        after[count] = rule.after;
        user_data[count] = rule.user_data;
        ++count;
    }
    if (count != 0U) ++g_interceptors.binder_matched;
    interceptor_unlock();
    return 0;
}

void binder_rule_release(const unsigned int *indices, unsigned int count)
{
    interceptor_lock();
    for (unsigned int item = 0U; item < count; ++item) {
        BinderRule &rule = g_interceptors.binder_rules[indices[item]];
        if (rule.in_flight != 0U) --rule.in_flight;
    }
    interceptor_unlock();
}

extern "C" __attribute__((noinline)) jboolean binder_transact_replacement(
    JNIEnv *env, jobject proxy, jint code, jobject data, jobject reply, jint flags)
{
    interceptor_prepare_process();
    __atomic_add_fetch(&g_interceptors.binder_wrappers, 1U, __ATOMIC_ACQ_REL);
    auto original = reinterpret_cast<BinderNative>(__atomic_load_n(
        &g_interceptors.binder_original, __ATOMIC_ACQUIRE));
    if (!original) {
        __atomic_sub_fetch(&g_interceptors.binder_wrappers, 1U, __ATOMIC_ACQ_REL);
        return JNI_FALSE;
    }
    bool nested = false;
    const bool tracked = interceptor_enter_thread(true, nested);
    if (!tracked || nested ||
        __atomic_load_n(&g_interceptors.binder_stopping, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&g_interceptors.binder_ready, __ATOMIC_ACQUIRE)) {
        const jboolean result = original(env, proxy, code, data, reply, flags);
        if (tracked) interceptor_leave_thread(true);
        __atomic_sub_fetch(&g_interceptors.binder_wrappers, 1U, __ATOMIC_ACQ_REL);
        return result;
    }
    __atomic_add_fetch(&g_interceptors.binder_calls, 1UL, __ATOMIC_RELAXED);
    char token[192];
    const unsigned long token_length =
        parcel_interface_token(env, data, token, sizeof(token));
    if (__atomic_load_n(&g_interceptors.binder_logging, __ATOMIC_RELAXED)) {
        api_log("rtgum-binder: transact");
        if (token_length != 0UL) api_log(token);
    }

    unsigned int indices[kInterceptorRuleCapacity]{};
    RtGumBinderInterceptor before[kInterceptorRuleCapacity]{};
    RtGumBinderInterceptor after[kInterceptorRuleCapacity]{};
    void *users[kInterceptorRuleCapacity]{};
    unsigned int rule_count = 0U;
    (void)binder_rule_snapshot(token, indices, before, after, users, rule_count);
    RtGumBinderCall call{};
    call.version = 1UL;
    call.size = sizeof(call);
    call.env = env;
    call.binder_proxy = proxy;
    call.code = code;
    call.flags = static_cast<unsigned int>(flags);
    call.data = data;
    call.reply = reply;
    call.interface_token = token;
    call.interface_token_length = token_length;
    for (unsigned int index = 0U; index < rule_count; ++index) {
        if (!before[index]) continue;
        const long callback = before[index](&call, users[index]);
        if (callback == RTGUM_INTERCEPT_SKIP_OR_OVERRIDE)
            call.skipped = 1U;
        else if (callback < 0)
            __atomic_add_fetch(&g_interceptors.binder_callback_errors, 1UL,
                               __ATOMIC_RELAXED);
    }
    if (call.skipped == 0U)
        call.result = original(env, proxy, code, data, reply, flags) != JNI_FALSE;
    for (unsigned int index = rule_count; index != 0U; --index) {
        if (!after[index - 1U]) continue;
        const long callback = after[index - 1U](&call, users[index - 1U]);
        if (callback < 0)
            __atomic_add_fetch(&g_interceptors.binder_callback_errors, 1UL,
                               __ATOMIC_RELAXED);
    }
    binder_rule_release(indices, rule_count);
    interceptor_leave_thread(true);
    __atomic_sub_fetch(&g_interceptors.binder_wrappers, 1U, __ATOMIC_ACQ_REL);
    return call.result != 0 ? JNI_TRUE : JNI_FALSE;
}

long linker_rule_snapshot(const char *filename, unsigned int *indices,
                          RtGumLinkerInterceptor *before,
                          RtGumLinkerInterceptor *after, void **user_data,
                          unsigned int &count)
{
    count = 0U;
    const char *safe_name = filename ? filename : "";
    interceptor_lock();
    for (unsigned int index = 0U; index < kInterceptorRuleCapacity; ++index) {
        LinkerRule &rule = g_interceptors.linker_rules[index];
        if (!rule.active ||
            !interceptor_match(safe_name, rule.name, rule.match_flags, false))
            continue;
        ++rule.in_flight;
        indices[count] = index;
        before[count] = rule.before;
        after[count] = rule.after;
        user_data[count] = rule.user_data;
        ++count;
    }
    if (count != 0U) ++g_interceptors.linker_matched;
    interceptor_unlock();
    return 0;
}

void linker_rule_release(const unsigned int *indices, unsigned int count)
{
    interceptor_lock();
    for (unsigned int item = 0U; item < count; ++item) {
        LinkerRule &rule = g_interceptors.linker_rules[indices[item]];
        if (rule.in_flight != 0U) --rule.in_flight;
    }
    interceptor_unlock();
}

const char *interceptor_base_name(const char *path)
{
    if (!path) return "";
    const char *base = path;
    for (const char *cursor = path; *cursor != '\0'; ++cursor)
        if (*cursor == '/') base = cursor + 1;
    return base;
}

bool lifecycle_rule_matches(const LifecycleRule &rule, const char *name)
{
    const char *safe = name ? name : "";
    if (interceptor_match(safe, rule.name, rule.match_flags, false)) return true;
    const char *base = interceptor_base_name(safe);
    return base != safe &&
           interceptor_match(base, rule.name, rule.match_flags, false);
}

unsigned int lifecycle_rule_snapshot(
    const char *name, unsigned int event_mask, unsigned int *indices,
    RtGumSoLifecycleCallback *callbacks, void **users)
{
    unsigned int count = 0U;
    interceptor_lock();
    for (unsigned int index = 0U; index < kInterceptorRuleCapacity; ++index) {
        LifecycleRule &rule = g_interceptors.lifecycle_rules[index];
        if (!rule.active || (rule.event_mask & event_mask) == 0U ||
            !lifecycle_rule_matches(rule, name))
            continue;
        ++rule.in_flight;
        indices[count] = index;
        callbacks[count] = rule.callback;
        users[count] = rule.user_data;
        ++count;
    }
    if (count != 0U) ++g_interceptors.lifecycle_matched;
    interceptor_unlock();
    return count;
}

void lifecycle_rule_release(const unsigned int *indices, unsigned int count)
{
    interceptor_lock();
    for (unsigned int item = 0U; item < count; ++item) {
        LifecycleRule &rule = g_interceptors.lifecycle_rules[indices[item]];
        if (rule.in_flight != 0U) --rule.in_flight;
    }
    interceptor_unlock();
}

void lifecycle_dispatch(const RtGumSoLifecycleEvent &event,
                        RtGumSoLifecycleCallback *callbacks,
                        void **users, unsigned int count, bool reverse)
{
    for (unsigned int item = 0U; item < count; ++item) {
        const unsigned int index = reverse ? count - item - 1U : item;
        if (callbacks[index] && callbacks[index](&event, users[index]) < 0)
            __atomic_add_fetch(&g_interceptors.lifecycle_callback_errors, 1UL,
                               __ATOMIC_RELAXED);
    }
}

extern "C" __attribute__((noinline)) void constructors_replacement(void *soinfo)
{
    interceptor_prepare_process();
    __atomic_add_fetch(&g_interceptors.constructors_wrappers, 1U,
                       __ATOMIC_ACQ_REL);
    auto original = reinterpret_cast<SoinfoCallConstructors>(__atomic_load_n(
        &g_interceptors.constructors_original, __ATOMIC_ACQUIRE));
    if (!original ||
        __atomic_load_n(&g_interceptors.constructors_stopping,
                        __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&g_interceptors.constructors_ready,
                         __ATOMIC_ACQUIRE)) {
        if (original) original(soinfo);
        __atomic_sub_fetch(&g_interceptors.constructors_wrappers, 1U,
                           __ATOMIC_ACQ_REL);
        return;
    }
    __atomic_add_fetch(&g_interceptors.lifecycle_calls, 1UL,
                       __ATOMIC_RELAXED);
    SoinfoGetRealpath get_realpath = g_interceptors.soinfo_get_realpath;
    const char *name = get_realpath && soinfo ? get_realpath(soinfo) : "";
    if (!name) name = "";
    unsigned int indices[kInterceptorRuleCapacity]{};
    RtGumSoLifecycleCallback callbacks[kInterceptorRuleCapacity]{};
    void *users[kInterceptorRuleCapacity]{};
    const unsigned int count = lifecycle_rule_snapshot(
        name, RTGUM_SO_EVENT_CONSTRUCTORS, indices, callbacks, users);
    RtGumSoLifecycleEvent event{};
    event.version = 1UL;
    event.size = sizeof(event);
    event.library_name = name;
    event.soinfo = soinfo;
    event.address = g_interceptors.constructors_target;
    event.phase = RTGUM_SO_PHASE_BEFORE_CONSTRUCTORS;
    lifecycle_dispatch(event, callbacks, users, count, false);
    original(soinfo);
    event.phase = RTGUM_SO_PHASE_AFTER_CONSTRUCTORS;
    lifecycle_dispatch(event, callbacks, users, count, true);
    lifecycle_rule_release(indices, count);
    __atomic_sub_fetch(&g_interceptors.constructors_wrappers, 1U,
                       __ATOMIC_ACQ_REL);
}

bool trace_pattern_match(const char *text, const char *pattern,
                         unsigned int flags)
{
    if (!pattern || pattern[0] == '\0' ||
        (pattern[0] == '*' && pattern[1] == '\0'))
        return true;
    return interceptor_match(text ? text : "", pattern, flags, true);
}

unsigned int jni_rule_snapshot(
    const char *class_name, const char *method_name, const char *signature,
    unsigned int *indices, RtGumJniTraceCallback *callbacks, void **users)
{
    unsigned int count = 0U;
    interceptor_lock();
    for (unsigned int index = 0U; index < kInterceptorRuleCapacity; ++index) {
        JniTraceRule &rule = g_interceptors.jni_rules[index];
        if (!rule.active ||
            !trace_pattern_match(class_name, rule.class_name, rule.match_flags) ||
            !trace_pattern_match(method_name, rule.method_name, rule.match_flags) ||
            !trace_pattern_match(signature, rule.signature, rule.match_flags))
            continue;
        ++rule.in_flight;
        indices[count] = index;
        callbacks[count] = rule.callback;
        users[count] = rule.user_data;
        ++count;
    }
    if (count != 0U) ++g_interceptors.jni_matched;
    interceptor_unlock();
    return count;
}

void jni_rule_release(const unsigned int *indices, unsigned int count)
{
    interceptor_lock();
    for (unsigned int item = 0U; item < count; ++item) {
        JniTraceRule &rule = g_interceptors.jni_rules[indices[item]];
        if (rule.in_flight != 0U) --rule.in_flight;
    }
    interceptor_unlock();
}

bool jni_class_name(JNIEnv *env, jclass clazz, char *output,
                    unsigned long capacity)
{
    if (!env || !clazz || !output || capacity == 0UL ||
        !g_interceptors.class_get_name)
        return false;
    output[0] = '\0';
    auto name = static_cast<jstring>(env->CallObjectMethod(
        clazz, g_interceptors.class_get_name));
    if (env->ExceptionCheck() || !name) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (name) env->DeleteLocalRef(name);
        return false;
    }
    const char *characters = env->GetStringUTFChars(name, nullptr);
    if (env->ExceptionCheck() || !characters) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(name);
        return false;
    }
    unsigned long cursor = 0UL;
    while (characters[cursor] != '\0' && cursor + 1UL < capacity) {
        const char value = characters[cursor];
        output[cursor] = value == '.' ? '/' : value;
        ++cursor;
    }
    output[cursor] = '\0';
    const bool complete = characters[cursor] == '\0';
    env->ReleaseStringUTFChars(name, characters);
    env->DeleteLocalRef(name);
    return complete;
}

void jni_trace_dispatch(JNIEnv *env, jclass clazz, const char *class_name,
                        const JNINativeMethod &method, unsigned int phase,
                        jint result)
{
    unsigned int indices[kInterceptorRuleCapacity]{};
    RtGumJniTraceCallback callbacks[kInterceptorRuleCapacity]{};
    void *users[kInterceptorRuleCapacity]{};
    const char *method_name = method.name ? method.name : "";
    const char *signature = method.signature ? method.signature : "";
    const unsigned int count = jni_rule_snapshot(
        class_name, method_name, signature, indices, callbacks, users);
    RtGumJniTraceEvent event{};
    event.version = 1UL;
    event.size = sizeof(event);
    event.env = env;
    event.clazz = clazz;
    event.class_name = class_name;
    event.method_name = method_name;
    event.signature = signature;
    event.function = reinterpret_cast<unsigned long>(method.fnPtr);
    event.phase = phase;
    event.register_result = result;
    for (unsigned int item = 0U; item < count; ++item)
        if (callbacks[item] && callbacks[item](&event, users[item]) < 0)
            __atomic_add_fetch(&g_interceptors.jni_callback_errors, 1UL,
                               __ATOMIC_RELAXED);
    jni_rule_release(indices, count);
}

extern "C" __attribute__((noinline)) jint register_natives_replacement(
    JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint method_count)
{
    interceptor_prepare_process();
    __atomic_add_fetch(&g_interceptors.register_natives_wrappers, 1U,
                       __ATOMIC_ACQ_REL);
    auto original = reinterpret_cast<RegisterNatives>(__atomic_load_n(
        &g_interceptors.register_natives_original, __ATOMIC_ACQUIRE));
    if (!original) {
        __atomic_sub_fetch(&g_interceptors.register_natives_wrappers, 1U,
                           __ATOMIC_ACQ_REL);
        return JNI_ERR;
    }
    bool nested = false;
    const bool tracked = interceptor_enter_jni_thread(nested);
    const bool usable = tracked && !nested && env && clazz && methods &&
        method_count > 0 && method_count <= 4096 &&
        !__atomic_load_n(&g_interceptors.register_natives_stopping,
                         __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&g_interceptors.register_natives_ready,
                        __ATOMIC_ACQUIRE);
    char class_name[kInterceptorTextCapacity]{};
    const bool named = usable &&
        jni_class_name(env, clazz, class_name, sizeof(class_name));
    if (named) {
        __atomic_add_fetch(&g_interceptors.jni_calls, 1UL, __ATOMIC_RELAXED);
        for (jint index = 0; index < method_count; ++index)
            jni_trace_dispatch(env, clazz, class_name, methods[index],
                               RTGUM_JNI_TRACE_PHASE_BEFORE_REGISTER, JNI_OK);
    }
    const jint result = original(env, clazz, methods, method_count);
    if (named)
        for (jint index = method_count; index > 0; --index)
            jni_trace_dispatch(env, clazz, class_name, methods[index - 1],
                               RTGUM_JNI_TRACE_PHASE_AFTER_REGISTER, result);
    if (tracked) interceptor_leave_jni_thread();
    __atomic_sub_fetch(&g_interceptors.register_natives_wrappers, 1U,
                       __ATOMIC_ACQ_REL);
    return result;
}

jint jni_onload_dispatch(unsigned int slot_index, JavaVM *vm, void *reserved)
{
    if (slot_index >= kJniOnLoadHookCapacity) return JNI_ERR;
    interceptor_prepare_process();
    interceptor_lock();
    JniOnLoadHook &slot = g_interceptors.jni_onload_hooks[slot_index];
    if (!slot.active || slot.original == 0UL) {
        interceptor_unlock();
        return JNI_ERR;
    }
    ++slot.wrappers;
    const unsigned long original_address = slot.original;
    const unsigned long target = slot.target;
    const unsigned long hook_handle = slot.hook_handle;
    char name[kInterceptorTextCapacity];
    bounded_copy(name, sizeof(name), slot.name);
    interceptor_unlock();
    unsigned int indices[kInterceptorRuleCapacity]{};
    RtGumSoLifecycleCallback callbacks[kInterceptorRuleCapacity]{};
    void *users[kInterceptorRuleCapacity]{};
    const unsigned int count = lifecycle_rule_snapshot(
        name, RTGUM_SO_EVENT_JNI_ONLOAD, indices, callbacks, users);
    RtGumSoLifecycleEvent event{};
    event.version = 1UL;
    event.size = sizeof(event);
    event.library_name = name;
    event.address = target;
    event.phase = RTGUM_SO_PHASE_BEFORE_JNI_ONLOAD;
    event.vm = vm;
    event.reserved = reserved;

    /* We have already left the patched entry and are executing from Daemon
     * ghost code.  Remove this one-shot entry patch before callbacks run while
     * retaining its original trampoline until the call completes.  A module
     * may then hook another function on the same code page during JNI_OnLoad
     * (a common layout for small libraries) without trying to read through an
     * active execute-only shadow view. */
    long retired = g_shadow_engine.Deactivate(hook_handle);
    if (retired != 0)
        __atomic_add_fetch(&g_interceptors.lifecycle_callback_errors, 1UL,
                           __ATOMIC_RELAXED);
    lifecycle_dispatch(event, callbacks, users, count, false);
    const jint result = reinterpret_cast<JniOnLoad>(original_address)(vm, reserved);
    event.phase = RTGUM_SO_PHASE_AFTER_JNI_ONLOAD;
    event.result = result;
    lifecycle_dispatch(event, callbacks, users, count, true);
    lifecycle_rule_release(indices, count);

    /* ART serializes native-library loads.  JNI_OnLoad is therefore a natural
     * one-shot hook: removing it here prevents a later dlclose/address-reuse
     * cycle from inheriting a stale target.  We are executing in Daemon ghost
     * code and the original trampoline has already returned, so both Shadow
     * records can be retired safely. */
    if (retired != 0) retired = g_shadow_engine.Deactivate(hook_handle);
    if (retired == 0) retired = g_shadow_engine.Finalize(hook_handle);
    interceptor_lock();
    if (slot.hook_handle == hook_handle) {
        if (slot.wrappers != 0U) --slot.wrappers;
        if (retired == 0 && slot.wrappers == 0U) slot = {};
    }
    interceptor_unlock();
    return result;
}

#define RTGUM_JNI_ONLOAD_WRAPPER(index)                                      \
    extern "C" __attribute__((noinline)) jint jni_onload_wrapper_##index(  \
        JavaVM *vm, void *reserved)                                          \
    {                                                                        \
        return jni_onload_dispatch(index, vm, reserved);                     \
    }
RTGUM_JNI_ONLOAD_WRAPPER(0)
RTGUM_JNI_ONLOAD_WRAPPER(1)
RTGUM_JNI_ONLOAD_WRAPPER(2)
RTGUM_JNI_ONLOAD_WRAPPER(3)
RTGUM_JNI_ONLOAD_WRAPPER(4)
RTGUM_JNI_ONLOAD_WRAPPER(5)
RTGUM_JNI_ONLOAD_WRAPPER(6)
RTGUM_JNI_ONLOAD_WRAPPER(7)
#undef RTGUM_JNI_ONLOAD_WRAPPER

using JniOnLoadWrapper = jint (*)(JavaVM *, void *);
JniOnLoadWrapper const kJniOnLoadWrappers[kJniOnLoadHookCapacity] = {
    jni_onload_wrapper_0, jni_onload_wrapper_1, jni_onload_wrapper_2,
    jni_onload_wrapper_3, jni_onload_wrapper_4, jni_onload_wrapper_5,
    jni_onload_wrapper_6, jni_onload_wrapper_7,
};

bool lifecycle_has_jni_match(const char *name)
{
    bool matched = false;
    interceptor_lock();
    for (const LifecycleRule &rule : g_interceptors.lifecycle_rules)
        if (rule.active && (rule.event_mask & RTGUM_SO_EVENT_JNI_ONLOAD) != 0U &&
            lifecycle_rule_matches(rule, name)) {
            matched = true;
            break;
        }
    interceptor_unlock();
    return matched;
}

long arm_jni_onload_hook(const char *filename)
{
    if (!filename || !lifecycle_has_jni_match(filename)) return 0L;
    const char *soname = interceptor_base_name(filename);
    unsigned long target = 0UL;
    long result = host_find_export(soname, "JNI_OnLoad", &target);
    if (result != 0 || target == 0UL) return RTGUM_HOST_ERR_NOENT;

    unsigned int slot_index = kJniOnLoadHookCapacity;
    interceptor_lock();
    for (unsigned int index = 0U; index < kJniOnLoadHookCapacity; ++index) {
        JniOnLoadHook &slot = g_interceptors.jni_onload_hooks[index];
        if (slot.active && slot.target == target) {
            interceptor_unlock();
            return 0L;
        }
        if (!slot.active && slot_index == kJniOnLoadHookCapacity)
            slot_index = index;
    }
    if (slot_index == kJniOnLoadHookCapacity) {
        interceptor_unlock();
        return RTGUM_HOST_ERR_BUSY;
    }
    JniOnLoadHook &slot = g_interceptors.jni_onload_hooks[slot_index];
    slot = {};
    slot.active = true; /* reserves the slot against concurrent dlopen calls */
    slot.target = target;
    /* APK zip paths routinely exceed the fixed rule text capacity.  Store the
     * basename used for symbol resolution; otherwise truncation drops the
     * trailing SONAME and the one-shot wrapper cannot redispatch its rule. */
    bounded_copy(slot.name, sizeof(slot.name), soname);
    interceptor_unlock();

    unsigned long original = 0UL;
    unsigned long handle = 0UL;
    result = g_shadow_engine.Replace(
        target, reinterpret_cast<unsigned long>(kJniOnLoadWrappers[slot_index]),
        true, &original, &handle);
    interceptor_lock();
    if (slot.active && slot.target == target) {
        if (result == 0) {
            slot.original = original;
            slot.hook_handle = handle;
        } else {
            slot = {};
        }
    }
    interceptor_unlock();
    return result;
}

extern "C" __attribute__((noinline)) void *linker_dlopen_replacement(
    const char *filename, int flags, const void *extinfo, const void *caller)
{
    interceptor_prepare_process();
    __atomic_add_fetch(&g_interceptors.linker_wrappers, 1U, __ATOMIC_ACQ_REL);
    auto original = reinterpret_cast<LinkerDlopen>(__atomic_load_n(
        &g_interceptors.linker_original, __ATOMIC_ACQUIRE));
    if (!original) {
        __atomic_sub_fetch(&g_interceptors.linker_wrappers, 1U, __ATOMIC_ACQ_REL);
        return nullptr;
    }
    bool nested = false;
    const bool tracked = interceptor_enter_thread(false, nested);
    if (!tracked || nested ||
        __atomic_load_n(&g_interceptors.linker_stopping, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&g_interceptors.linker_ready, __ATOMIC_ACQUIRE)) {
        void *result = original(filename, flags, extinfo, caller);
        if (tracked) interceptor_leave_thread(false);
        __atomic_sub_fetch(&g_interceptors.linker_wrappers, 1U, __ATOMIC_ACQ_REL);
        return result;
    }
    __atomic_add_fetch(&g_interceptors.linker_calls, 1UL, __ATOMIC_RELAXED);
    unsigned int indices[kInterceptorRuleCapacity]{};
    RtGumLinkerInterceptor before[kInterceptorRuleCapacity]{};
    RtGumLinkerInterceptor after[kInterceptorRuleCapacity]{};
    void *users[kInterceptorRuleCapacity]{};
    unsigned int rule_count = 0U;
    (void)linker_rule_snapshot(filename, indices, before, after, users, rule_count);
    RtGumLinkerCall call{};
    call.version = 1UL;
    call.size = sizeof(call);
    call.filename = filename ? filename : "";
    call.flags = flags;
    call.extinfo = extinfo;
    call.caller_address = caller;
    for (unsigned int index = 0U; index < rule_count; ++index) {
        if (!before[index]) continue;
        const long callback = before[index](&call, users[index]);
        if (callback == RTGUM_INTERCEPT_SKIP_OR_OVERRIDE)
            call.skipped = 1U;
        else if (callback < 0)
            __atomic_add_fetch(&g_interceptors.linker_callback_errors, 1UL,
                               __ATOMIC_RELAXED);
    }
    if (call.skipped == 0U) {
        call.result = original(filename, flags, extinfo, caller);
        if (call.result && filename) {
            const long armed = arm_jni_onload_hook(filename);
            if (armed != 0 && armed != RTGUM_HOST_ERR_NOENT) {
                __atomic_add_fetch(&g_interceptors.lifecycle_callback_errors,
                                   1UL, __ATOMIC_RELAXED);
                api_log("rtgum-lifecycle: JNI_OnLoad arm failed");
            }
        }
    }
    for (unsigned int index = rule_count; index != 0U; --index) {
        if (!after[index - 1U]) continue;
        const long callback = after[index - 1U](&call, users[index - 1U]);
        if (callback < 0)
            __atomic_add_fetch(&g_interceptors.linker_callback_errors, 1UL,
                               __ATOMIC_RELAXED);
    }
    linker_rule_release(indices, rule_count);
    interceptor_leave_thread(false);
    __atomic_sub_fetch(&g_interceptors.linker_wrappers, 1U, __ATOMIC_ACQ_REL);
    return call.result;
}

unsigned long decode_linker_thunk(unsigned long thunk)
{
    unsigned int words[2]{};
    if (resolver_memory_read(thunk, words, sizeof(words)) != 0) return 0UL;
    unsigned long branch_pc = thunk;
    unsigned int branch = words[0];
    if (rtgum::shadow::IsBti(words[0])) {
        branch_pc += 4UL;
        branch = words[1];
    }
    if ((branch & 0xfc000000U) != 0x14000000U) return 0UL;
    long displacement = static_cast<long>(branch & 0x03ffffffU);
    if ((displacement & 0x02000000L) != 0L)
        displacement |= ~0x03ffffffL;
    displacement <<= 2;
    return static_cast<unsigned long>(static_cast<long>(branch_pc) + displacement);
}

long ensure_binder_interceptor()
{
    for (;;) {
        interceptor_lock();
        if (g_interceptors.binder_ready) {
            const bool stopping = g_interceptors.binder_stopping;
            interceptor_unlock();
            return stopping ? RTGUM_HOST_ERR_BUSY : 0L;
        }
        if (!g_interceptors.binder_starting) {
            g_interceptors.binder_starting = true;
            interceptor_unlock();
            break;
        }
        interceptor_unlock();
        (void)host_sleep_ms(1U);
    }
    long result = prepare_parcel_bridge();
    DexEnv attached{};
    if (result == 0) result = dex_attach(attached);
    unsigned long target = 0UL;
    if (result == 0) {
        jclass binder = attached.env->FindClass(RTGUM_BINDER_CLASS);
        jmethodID method = binder ? attached.env->GetMethodID(
            binder, RTGUM_BINDER_NAME, RTGUM_BINDER_SIG) : nullptr;
        if (attached.env->ExceptionCheck()) attached.env->ExceptionClear();
        if (!binder || !method)
            result = RTGUM_HOST_ERR_NOENT;
        else
            result = decode_native_art_method(
                method,
                reinterpret_cast<unsigned long>(
                    g_interceptors.parcel.parcel_for_java),
                target);
        if (binder) attached.env->DeleteLocalRef(binder);
    }
    dex_detach(attached);
    unsigned long handle = 0UL;
    if (result == 0)
        result = g_shadow_engine.Replace(
            target, reinterpret_cast<unsigned long>(&binder_transact_replacement),
            true, &g_interceptors.binder_original, &handle);
    interceptor_lock();
    if (result == 0) {
        g_interceptors.binder_hook_handle = handle;
        g_interceptors.binder_ready = true;
        g_interceptors.binder_stopping = false;
    } else {
        g_interceptors.binder_original = 0UL;
    }
    g_interceptors.binder_starting = false;
    interceptor_unlock();
    api_log(result == 0 ? "rtgum-interceptor: binder ready"
                        : "rtgum-interceptor: binder init failed");
    return result;
}

long ensure_linker_interceptor()
{
    for (;;) {
        interceptor_lock();
        if (g_interceptors.linker_ready) {
            const bool stopping = g_interceptors.linker_stopping;
            interceptor_unlock();
            return stopping ? RTGUM_HOST_ERR_BUSY : 0L;
        }
        if (!g_interceptors.linker_starting) {
            g_interceptors.linker_starting = true;
            interceptor_unlock();
            break;
        }
        interceptor_unlock();
        (void)host_sleep_ms(1U);
    }
    unsigned long thunk = 0UL;
    long result = resolve_named_symbol("ld-android.so",
                                       "__loader_android_dlopen_ext", &thunk);
    if (result != 0 || thunk == 0UL)
        result = resolve_named_symbol("linker64",
                                      "__loader_android_dlopen_ext", &thunk);
    const unsigned long target = result == 0 ? decode_linker_thunk(thunk) : 0UL;
    if (result == 0 && target == 0UL) result = RTGUM_HOST_ERR_NOTSUP;
    unsigned long handle = 0UL;
    if (result == 0)
        result = g_shadow_engine.Replace(
            target, reinterpret_cast<unsigned long>(&linker_dlopen_replacement),
            true, &g_interceptors.linker_original, &handle);
    interceptor_lock();
    if (result == 0) {
        g_interceptors.linker_hook_handle = handle;
        g_interceptors.linker_ready = true;
        g_interceptors.linker_stopping = false;
    } else {
        g_interceptors.linker_original = 0UL;
    }
    g_interceptors.linker_starting = false;
    interceptor_unlock();
    api_log(result == 0 ? "rtgum-interceptor: linker ready"
                        : "rtgum-interceptor: linker init failed");
    return result;
}

long ensure_constructors_interceptor()
{
    for (;;) {
        interceptor_lock();
        if (g_interceptors.constructors_ready) {
            const bool stopping = g_interceptors.constructors_stopping;
            interceptor_unlock();
            return stopping ? RTGUM_HOST_ERR_BUSY : 0L;
        }
        if (!g_interceptors.constructors_starting) {
            g_interceptors.constructors_starting = true;
            interceptor_unlock();
            break;
        }
        interceptor_unlock();
        (void)host_sleep_ms(1U);
    }
    constexpr const char *kCallConstructors =
        "__dl__ZN6soinfo17call_constructorsEv";
    constexpr const char *kGetRealpath = "__dl__ZNK6soinfo12get_realpathEv";
    unsigned long target = 0UL;
    unsigned long get_realpath = 0UL;
    long result = resolve_named_symbol("ld-android.so", kCallConstructors,
                                       &target);
    if (result != 0 || target == 0UL)
        result = resolve_named_symbol("linker64", kCallConstructors, &target);
    if (result == 0)
        result = resolve_named_symbol("ld-android.so", kGetRealpath,
                                      &get_realpath);
    if ((result != 0 || get_realpath == 0UL) && target != 0UL)
        result = resolve_named_symbol("linker64", kGetRealpath, &get_realpath);
    unsigned long handle = 0UL;
    unsigned long original = 0UL;
    if (result == 0 && target != 0UL && get_realpath != 0UL)
        result = g_shadow_engine.Replace(
            target, reinterpret_cast<unsigned long>(&constructors_replacement),
            true, &original, &handle);
    else if (result == 0)
        result = RTGUM_HOST_ERR_NOENT;
    interceptor_lock();
    if (result == 0) {
        g_interceptors.constructors_target = target;
        g_interceptors.constructors_original = original;
        g_interceptors.constructors_hook_handle = handle;
        g_interceptors.soinfo_get_realpath =
            reinterpret_cast<SoinfoGetRealpath>(get_realpath);
        g_interceptors.constructors_ready = true;
        g_interceptors.constructors_stopping = false;
    } else {
        g_interceptors.constructors_target = 0UL;
        g_interceptors.constructors_original = 0UL;
        g_interceptors.soinfo_get_realpath = nullptr;
    }
    g_interceptors.constructors_starting = false;
    interceptor_unlock();
    api_log(result == 0 ? "rtgum-lifecycle: constructors ready"
                        : "rtgum-lifecycle: constructors init failed");
    return result;
}

long ensure_register_natives_interceptor()
{
    for (;;) {
        interceptor_lock();
        if (g_interceptors.register_natives_ready) {
            const bool stopping = g_interceptors.register_natives_stopping;
            interceptor_unlock();
            return stopping ? RTGUM_HOST_ERR_BUSY : 0L;
        }
        if (!g_interceptors.register_natives_starting) {
            g_interceptors.register_natives_starting = true;
            interceptor_unlock();
            break;
        }
        interceptor_unlock();
        (void)host_sleep_ms(1U);
    }
    static_assert(
        offsetof(JNINativeInterface, RegisterNatives) / sizeof(void *) ==
            RTGUM_JNI_REGISTER_NATIVES_INDEX,
        "JNI RegisterNatives table index changed");
    DexEnv attached{};
    long result = dex_attach(attached);
    unsigned long target = 0UL;
    jmethodID class_get_name = nullptr;
    if (result == 0) {
        jclass class_class = attached.env->FindClass("java/lang/Class");
        class_get_name = class_class ? attached.env->GetMethodID(
            class_class, "getName", "()Ljava/lang/String;") : nullptr;
        if (attached.env->ExceptionCheck()) attached.env->ExceptionClear();
        if (!class_class || !class_get_name || !attached.env->functions ||
            !attached.env->functions->RegisterNatives)
            result = RTGUM_HOST_ERR_NOENT;
        else
            target = reinterpret_cast<unsigned long>(
                attached.env->functions->RegisterNatives);
        if (class_class) attached.env->DeleteLocalRef(class_class);
    }
    dex_detach(attached);
    unsigned long handle = 0UL;
    unsigned long original = 0UL;
    if (result == 0)
        result = g_shadow_engine.Replace(
            target, reinterpret_cast<unsigned long>(&register_natives_replacement),
            true, &original, &handle);
    interceptor_lock();
    if (result == 0) {
        g_interceptors.register_natives_original = original;
        g_interceptors.register_natives_hook_handle = handle;
        g_interceptors.class_get_name = class_get_name;
        g_interceptors.register_natives_ready = true;
        g_interceptors.register_natives_stopping = false;
    } else {
        g_interceptors.register_natives_original = 0UL;
        g_interceptors.class_get_name = nullptr;
    }
    g_interceptors.register_natives_starting = false;
    interceptor_unlock();
    api_log(result == 0 ? "rtgum-jni-trace: RegisterNatives ready"
                        : "rtgum-jni-trace: RegisterNatives init failed");
    return result;
}

unsigned int active_binder_rules()
{
    unsigned int count = 0U;
    for (const BinderRule &rule : g_interceptors.binder_rules)
        if (rule.active) ++count;
    return count;
}

unsigned int active_linker_rules()
{
    unsigned int count = 0U;
    for (const LinkerRule &rule : g_interceptors.linker_rules)
        if (rule.active) ++count;
    return count;
}

unsigned int active_lifecycle_rules()
{
    unsigned int count = 0U;
    for (const LifecycleRule &rule : g_interceptors.lifecycle_rules)
        if (rule.active) ++count;
    return count;
}

unsigned int active_jni_rules()
{
    unsigned int count = 0U;
    for (const JniTraceRule &rule : g_interceptors.jni_rules)
        if (rule.active) ++count;
    return count;
}

unsigned int active_linker_consumers()
{
    return active_linker_rules() + active_lifecycle_rules();
}

long stop_binder_interceptor()
{
    interceptor_lock();
    if (!g_interceptors.binder_ready) {
        interceptor_unlock();
        return 0;
    }
    if (active_binder_rules() != 0U || g_interceptors.binder_starting) {
        interceptor_unlock();
        return RTGUM_HOST_ERR_BUSY;
    }
    g_interceptors.binder_stopping = true;
    const unsigned long handle = g_interceptors.binder_hook_handle;
    interceptor_unlock();
    long result = g_shadow_engine.Deactivate(handle);
    if (result != 0) {
        interceptor_lock();
        g_interceptors.binder_stopping = false;
        interceptor_unlock();
        return result;
    }
    for (unsigned int attempt = 0U;
         attempt < 2000U && __atomic_load_n(&g_interceptors.binder_wrappers,
                                            __ATOMIC_ACQUIRE) != 0U;
         ++attempt)
        (void)host_sleep_ms(1U);
    if (__atomic_load_n(&g_interceptors.binder_wrappers, __ATOMIC_ACQUIRE) != 0U)
        return RTGUM_HOST_ERR_BUSY;
    result = g_shadow_engine.Finalize(handle);
    if (result != 0) return result;
    interceptor_lock();
    g_interceptors.binder_ready = false;
    g_interceptors.binder_stopping = false;
    g_interceptors.binder_hook_handle = 0UL;
    g_interceptors.binder_original = 0UL;
    interceptor_unlock();
    return 0;
}

long stop_linker_interceptor()
{
    interceptor_lock();
    if (!g_interceptors.linker_ready) {
        interceptor_unlock();
        return 0;
    }
    if (active_linker_consumers() != 0U || g_interceptors.linker_starting) {
        interceptor_unlock();
        return RTGUM_HOST_ERR_BUSY;
    }
    g_interceptors.linker_stopping = true;
    const unsigned long handle = g_interceptors.linker_hook_handle;
    interceptor_unlock();
    long result = g_shadow_engine.Deactivate(handle);
    if (result != 0) {
        interceptor_lock();
        g_interceptors.linker_stopping = false;
        interceptor_unlock();
        return result;
    }
    for (unsigned int attempt = 0U;
         attempt < 2000U && __atomic_load_n(&g_interceptors.linker_wrappers,
                                            __ATOMIC_ACQUIRE) != 0U;
         ++attempt)
        (void)host_sleep_ms(1U);
    if (__atomic_load_n(&g_interceptors.linker_wrappers, __ATOMIC_ACQUIRE) != 0U)
        return RTGUM_HOST_ERR_BUSY;
    result = g_shadow_engine.Finalize(handle);
    if (result != 0) return result;
    interceptor_lock();
    g_interceptors.linker_ready = false;
    g_interceptors.linker_stopping = false;
    g_interceptors.linker_hook_handle = 0UL;
    g_interceptors.linker_original = 0UL;
    interceptor_unlock();
    return 0;
}

long stop_constructors_interceptor()
{
    interceptor_lock();
    if (!g_interceptors.constructors_ready) {
        interceptor_unlock();
        return 0L;
    }
    if (active_lifecycle_rules() != 0U ||
        g_interceptors.constructors_starting) {
        interceptor_unlock();
        return RTGUM_HOST_ERR_BUSY;
    }
    g_interceptors.constructors_stopping = true;
    const unsigned long handle = g_interceptors.constructors_hook_handle;
    interceptor_unlock();
    long result = g_shadow_engine.Deactivate(handle);
    if (result != 0) {
        interceptor_lock();
        g_interceptors.constructors_stopping = false;
        interceptor_unlock();
        return result;
    }
    for (unsigned int attempt = 0U;
         attempt < 2000U &&
         __atomic_load_n(&g_interceptors.constructors_wrappers,
                         __ATOMIC_ACQUIRE) != 0U;
         ++attempt)
        (void)host_sleep_ms(1U);
    if (__atomic_load_n(&g_interceptors.constructors_wrappers,
                        __ATOMIC_ACQUIRE) != 0U)
        return RTGUM_HOST_ERR_BUSY;
    result = g_shadow_engine.Finalize(handle);
    if (result != 0) return result;
    interceptor_lock();
    g_interceptors.constructors_ready = false;
    g_interceptors.constructors_stopping = false;
    g_interceptors.constructors_hook_handle = 0UL;
    g_interceptors.constructors_original = 0UL;
    g_interceptors.constructors_target = 0UL;
    g_interceptors.soinfo_get_realpath = nullptr;
    interceptor_unlock();
    return 0L;
}

long stop_jni_onload_hooks()
{
    unsigned long handles[kJniOnLoadHookCapacity]{};
    unsigned int slots[kJniOnLoadHookCapacity]{};
    unsigned int count = 0U;
    interceptor_lock();
    for (unsigned int index = 0U; index < kJniOnLoadHookCapacity; ++index) {
        JniOnLoadHook &slot = g_interceptors.jni_onload_hooks[index];
        if (!slot.active) continue;
        if (slot.hook_handle == 0UL) {
            slot = {};
            continue;
        }
        slot.retiring = true;
        slots[count] = index;
        handles[count] = slot.hook_handle;
        ++count;
    }
    interceptor_unlock();
    for (unsigned int item = 0U; item < count; ++item) {
        long result = g_shadow_engine.Deactivate(handles[item]);
        if (result != 0) return result;
    }
    for (unsigned int attempt = 0U; attempt < 2000U; ++attempt) {
        bool busy = false;
        interceptor_lock();
        for (unsigned int item = 0U; item < count; ++item)
            if (g_interceptors.jni_onload_hooks[slots[item]].wrappers != 0U) {
                busy = true;
                break;
            }
        interceptor_unlock();
        if (!busy) break;
        if (attempt == 1999U) return RTGUM_HOST_ERR_BUSY;
        (void)host_sleep_ms(1U);
    }
    for (unsigned int item = 0U; item < count; ++item) {
        const long result = g_shadow_engine.Finalize(handles[item]);
        if (result != 0) return result;
        interceptor_lock();
        JniOnLoadHook &slot = g_interceptors.jni_onload_hooks[slots[item]];
        if (slot.hook_handle == handles[item]) slot = {};
        interceptor_unlock();
    }
    return 0L;
}

long stop_register_natives_interceptor()
{
    interceptor_lock();
    if (!g_interceptors.register_natives_ready) {
        interceptor_unlock();
        return 0L;
    }
    if (active_jni_rules() != 0U ||
        g_interceptors.register_natives_starting) {
        interceptor_unlock();
        return RTGUM_HOST_ERR_BUSY;
    }
    g_interceptors.register_natives_stopping = true;
    const unsigned long handle = g_interceptors.register_natives_hook_handle;
    interceptor_unlock();
    long result = g_shadow_engine.Deactivate(handle);
    if (result != 0) {
        interceptor_lock();
        g_interceptors.register_natives_stopping = false;
        interceptor_unlock();
        return result;
    }
    for (unsigned int attempt = 0U;
         attempt < 2000U &&
         __atomic_load_n(&g_interceptors.register_natives_wrappers,
                         __ATOMIC_ACQUIRE) != 0U;
         ++attempt)
        (void)host_sleep_ms(1U);
    if (__atomic_load_n(&g_interceptors.register_natives_wrappers,
                        __ATOMIC_ACQUIRE) != 0U)
        return RTGUM_HOST_ERR_BUSY;
    result = g_shadow_engine.Finalize(handle);
    if (result != 0) return result;
    interceptor_lock();
    g_interceptors.register_natives_ready = false;
    g_interceptors.register_natives_stopping = false;
    g_interceptors.register_natives_hook_handle = 0UL;
    g_interceptors.register_natives_original = 0UL;
    g_interceptors.class_get_name = nullptr;
    interceptor_unlock();
    return 0L;
}

long stop_lifecycle_interceptors()
{
    long result = stop_jni_onload_hooks();
    const long constructors = stop_constructors_interceptor();
    if (result == 0) result = constructors;

    /* The linker hook is shared with ordinary dlopen rules.  Removing the
     * final lifecycle observer must leave that hook running when another
     * consumer still owns it, and that is a successful lifecycle teardown. */
    bool may_stop_linker = false;
    interceptor_lock();
    may_stop_linker = active_linker_consumers() == 0U;
    interceptor_unlock();
    if (may_stop_linker) {
        long linker = stop_linker_interceptor();
        if (linker == RTGUM_HOST_ERR_BUSY) {
            interceptor_lock();
            const bool shared = active_linker_consumers() != 0U;
            interceptor_unlock();
            if (shared) linker = 0L;
        }
        if (result == 0) result = linker;
    }
    return result;
}

long host_binder_interceptor_register(
    const char *token, unsigned int match_flags, RtGumBinderInterceptor before,
    RtGumBinderInterceptor after, void *user_data, unsigned long *out_handle)
{
    if (!token || (!before && !after) || !out_handle ||
        ghost_length(token, kInterceptorTextCapacity) >= kInterceptorTextCapacity ||
        (match_flags & ~(RTGUM_INTERCEPT_MATCH_EXACT |
                         RTGUM_INTERCEPT_MATCH_SUBSTRING)) != 0U ||
        (match_flags & RTGUM_INTERCEPT_MATCH_EXACT) != 0U &&
            (match_flags & RTGUM_INTERCEPT_MATCH_SUBSTRING) != 0U)
        return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0UL;
    const long ready = ensure_binder_interceptor();
    if (ready != 0) return ready;
    interceptor_lock();
    BinderRule *slot = nullptr;
    unsigned int index = 0U;
    for (; index < kInterceptorRuleCapacity; ++index)
        if (!g_interceptors.binder_rules[index].active &&
            g_interceptors.binder_rules[index].in_flight == 0U) {
            slot = &g_interceptors.binder_rules[index];
            break;
        }
    if (!slot) {
        interceptor_unlock();
        return RTGUM_HOST_ERR_BUSY;
    }
    unsigned int generation = ++g_interceptors.binder_generation;
    if (generation == 0U) generation = ++g_interceptors.binder_generation;
    const unsigned long handle = kBinderRuleTag |
        (static_cast<unsigned long>(generation) << 8UL) | index + 1UL;
    slot->handle = handle;
    slot->retired_handle = 0UL;
    slot->before = before;
    slot->after = after;
    slot->user_data = user_data;
    slot->match_flags = match_flags == 0U ? RTGUM_INTERCEPT_MATCH_EXACT
                                         : match_flags;
    bounded_copy(slot->token, sizeof(slot->token), token);
    slot->active = true;
    *out_handle = handle;
    interceptor_unlock();
    return 0;
}

long host_linker_interceptor_register(
    const char *name, unsigned int match_flags, RtGumLinkerInterceptor before,
    RtGumLinkerInterceptor after, void *user_data, unsigned long *out_handle)
{
    if (!name || (!before && !after) || !out_handle ||
        ghost_length(name, kInterceptorTextCapacity) >= kInterceptorTextCapacity ||
        (match_flags & ~(RTGUM_INTERCEPT_MATCH_EXACT |
                         RTGUM_INTERCEPT_MATCH_SUBSTRING)) != 0U ||
        (match_flags & RTGUM_INTERCEPT_MATCH_EXACT) != 0U &&
            (match_flags & RTGUM_INTERCEPT_MATCH_SUBSTRING) != 0U)
        return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0UL;
    const long ready = ensure_linker_interceptor();
    if (ready != 0) return ready;
    interceptor_lock();
    LinkerRule *slot = nullptr;
    unsigned int index = 0U;
    for (; index < kInterceptorRuleCapacity; ++index)
        if (!g_interceptors.linker_rules[index].active &&
            g_interceptors.linker_rules[index].in_flight == 0U) {
            slot = &g_interceptors.linker_rules[index];
            break;
        }
    if (!slot) {
        interceptor_unlock();
        return RTGUM_HOST_ERR_BUSY;
    }
    unsigned int generation = ++g_interceptors.linker_generation;
    if (generation == 0U) generation = ++g_interceptors.linker_generation;
    const unsigned long handle = kLinkerRuleTag |
        (static_cast<unsigned long>(generation) << 8UL) | index + 1UL;
    slot->handle = handle;
    slot->retired_handle = 0UL;
    slot->before = before;
    slot->after = after;
    slot->user_data = user_data;
    slot->match_flags = match_flags == 0U ? RTGUM_INTERCEPT_MATCH_SUBSTRING
                                         : match_flags;
    bounded_copy(slot->name, sizeof(slot->name), name);
    slot->active = true;
    *out_handle = handle;
    interceptor_unlock();
    return 0;
}

long host_so_lifecycle_register(
    const char *name, unsigned int match_flags, unsigned int event_mask,
    RtGumSoLifecycleCallback callback, void *user_data,
    unsigned long *out_handle)
{
    if (!name || !callback || !out_handle ||
        ghost_length(name, kInterceptorTextCapacity) >= kInterceptorTextCapacity ||
        event_mask == 0U ||
        (event_mask & ~(RTGUM_SO_EVENT_CONSTRUCTORS |
                        RTGUM_SO_EVENT_JNI_ONLOAD)) != 0U ||
        (match_flags & ~(RTGUM_INTERCEPT_MATCH_EXACT |
                         RTGUM_INTERCEPT_MATCH_SUBSTRING)) != 0U ||
        ((match_flags & RTGUM_INTERCEPT_MATCH_EXACT) != 0U &&
         (match_flags & RTGUM_INTERCEPT_MATCH_SUBSTRING) != 0U))
        return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0UL;
    long ready = ensure_constructors_interceptor();
    if (ready != 0) return ready;
    ready = ensure_linker_interceptor();
    if (ready != 0) {
        (void)stop_constructors_interceptor();
        return ready;
    }
    interceptor_lock();
    LifecycleRule *slot = nullptr;
    unsigned int index = 0U;
    for (; index < kInterceptorRuleCapacity; ++index)
        if (!g_interceptors.lifecycle_rules[index].active &&
            g_interceptors.lifecycle_rules[index].in_flight == 0U) {
            slot = &g_interceptors.lifecycle_rules[index];
            break;
        }
    if (!slot) {
        interceptor_unlock();
        (void)stop_constructors_interceptor();
        (void)stop_linker_interceptor();
        return RTGUM_HOST_ERR_BUSY;
    }
    unsigned int generation = ++g_interceptors.lifecycle_generation;
    if (generation == 0U) generation = ++g_interceptors.lifecycle_generation;
    const unsigned long handle = kLifecycleRuleTag |
        (static_cast<unsigned long>(generation) << 8UL) | index + 1UL;
    slot->handle = handle;
    slot->retired_handle = 0UL;
    slot->callback = callback;
    slot->user_data = user_data;
    slot->match_flags = match_flags == 0U ? RTGUM_INTERCEPT_MATCH_SUBSTRING
                                         : match_flags;
    slot->event_mask = event_mask;
    bounded_copy(slot->name, sizeof(slot->name), name);
    slot->active = true;
    *out_handle = handle;
    interceptor_unlock();
    return 0L;
}

void normalize_class_selector(char *destination, unsigned long capacity,
                              const char *source)
{
    if (!destination || capacity == 0UL) return;
    unsigned long cursor = 0UL;
    while (source && source[cursor] != '\0' && cursor + 1UL < capacity) {
        destination[cursor] = source[cursor] == '.' ? '/' : source[cursor];
        ++cursor;
    }
    destination[cursor] = '\0';
}

long host_jni_trace_register(
    const char *class_name, const char *method_name, const char *signature,
    unsigned int match_flags, RtGumJniTraceCallback callback, void *user_data,
    unsigned long *out_handle)
{
    if (!class_name || !method_name || !signature || !callback || !out_handle ||
        ghost_length(class_name, kInterceptorTextCapacity) >=
            kInterceptorTextCapacity ||
        ghost_length(method_name, kInterceptorTextCapacity) >=
            kInterceptorTextCapacity ||
        ghost_length(signature, kInterceptorTextCapacity) >=
            kInterceptorTextCapacity ||
        (match_flags & ~(RTGUM_INTERCEPT_MATCH_EXACT |
                         RTGUM_INTERCEPT_MATCH_SUBSTRING)) != 0U ||
        ((match_flags & RTGUM_INTERCEPT_MATCH_EXACT) != 0U &&
         (match_flags & RTGUM_INTERCEPT_MATCH_SUBSTRING) != 0U))
        return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0UL;
    const long ready = ensure_register_natives_interceptor();
    if (ready != 0) return ready;
    interceptor_lock();
    JniTraceRule *slot = nullptr;
    unsigned int index = 0U;
    for (; index < kInterceptorRuleCapacity; ++index)
        if (!g_interceptors.jni_rules[index].active &&
            g_interceptors.jni_rules[index].in_flight == 0U) {
            slot = &g_interceptors.jni_rules[index];
            break;
        }
    if (!slot) {
        interceptor_unlock();
        (void)stop_register_natives_interceptor();
        return RTGUM_HOST_ERR_BUSY;
    }
    unsigned int generation = ++g_interceptors.jni_generation;
    if (generation == 0U) generation = ++g_interceptors.jni_generation;
    const unsigned long handle = kJniTraceRuleTag |
        (static_cast<unsigned long>(generation) << 8UL) | index + 1UL;
    slot->handle = handle;
    slot->retired_handle = 0UL;
    slot->callback = callback;
    slot->user_data = user_data;
    slot->match_flags = match_flags == 0U ? RTGUM_INTERCEPT_MATCH_EXACT
                                         : match_flags;
    normalize_class_selector(slot->class_name, sizeof(slot->class_name),
                             class_name);
    bounded_copy(slot->method_name, sizeof(slot->method_name), method_name);
    bounded_copy(slot->signature, sizeof(slot->signature), signature);
    slot->active = true;
    *out_handle = handle;
    interceptor_unlock();
    return 0L;
}

long host_interceptor_unregister(unsigned long handle)
{
    const unsigned long tag = handle & 0xffff000000000000UL;
    const unsigned int id = static_cast<unsigned int>(handle & 0xffUL);
    if (id == 0U || id > kInterceptorRuleCapacity ||
        (tag != kBinderRuleTag && tag != kLinkerRuleTag &&
         tag != kLifecycleRuleTag && tag != kJniTraceRuleTag))
        return RTGUM_HOST_ERR_BADF;
    bool stop_binder = false;
    bool stop_linker = false;
    bool stop_lifecycle = false;
    bool stop_jni = false;
    interceptor_lock();
    if (tag == kBinderRuleTag) {
        BinderRule &rule = g_interceptors.binder_rules[id - 1U];
        if (!rule.active) {
            const bool retired = rule.retired_handle == handle;
            const bool retry_stop = retired &&
                g_interceptors.binder_stopping && active_binder_rules() == 0U;
            interceptor_unlock();
            if (!retired) return RTGUM_HOST_ERR_BADF;
            return retry_stop ? stop_binder_interceptor() : 0L;
        }
        if (rule.handle != handle) {
            interceptor_unlock();
            return RTGUM_HOST_ERR_BADF;
        }
        rule.active = false;
        if (rule.in_flight != 0U) {
            rule.active = true;
            interceptor_unlock();
            return RTGUM_HOST_ERR_BUSY;
        }
        rule.retired_handle = handle;
        rule.handle = 0UL;
        rule.before = nullptr;
        rule.after = nullptr;
        rule.user_data = nullptr;
        rule.token[0] = '\0';
        stop_binder = active_binder_rules() == 0U;
    } else if (tag == kLinkerRuleTag) {
        LinkerRule &rule = g_interceptors.linker_rules[id - 1U];
        if (!rule.active) {
            const bool retired = rule.retired_handle == handle;
            const bool retry_stop = retired &&
                g_interceptors.linker_stopping &&
                active_linker_consumers() == 0U;
            interceptor_unlock();
            if (!retired) return RTGUM_HOST_ERR_BADF;
            return retry_stop ? stop_linker_interceptor() : 0L;
        }
        if (rule.handle != handle) {
            interceptor_unlock();
            return RTGUM_HOST_ERR_BADF;
        }
        rule.active = false;
        if (rule.in_flight != 0U) {
            rule.active = true;
            interceptor_unlock();
            return RTGUM_HOST_ERR_BUSY;
        }
        rule.retired_handle = handle;
        rule.handle = 0UL;
        rule.before = nullptr;
        rule.after = nullptr;
        rule.user_data = nullptr;
        rule.name[0] = '\0';
        stop_linker = active_linker_consumers() == 0U;
    } else if (tag == kLifecycleRuleTag) {
        LifecycleRule &rule = g_interceptors.lifecycle_rules[id - 1U];
        if (!rule.active) {
            const bool retired = rule.retired_handle == handle;
            const bool retry_stop = retired && active_lifecycle_rules() == 0U;
            interceptor_unlock();
            if (!retired) return RTGUM_HOST_ERR_BADF;
            return retry_stop ? stop_lifecycle_interceptors() : 0L;
        }
        if (rule.handle != handle) {
            interceptor_unlock();
            return RTGUM_HOST_ERR_BADF;
        }
        rule.active = false;
        if (rule.in_flight != 0U) {
            rule.active = true;
            interceptor_unlock();
            return RTGUM_HOST_ERR_BUSY;
        }
        rule.retired_handle = handle;
        rule.handle = 0UL;
        rule.callback = nullptr;
        rule.user_data = nullptr;
        rule.event_mask = 0U;
        rule.name[0] = '\0';
        stop_lifecycle = active_lifecycle_rules() == 0U;
    } else {
        JniTraceRule &rule = g_interceptors.jni_rules[id - 1U];
        if (!rule.active) {
            const bool retired = rule.retired_handle == handle;
            const bool retry_stop = retired && active_jni_rules() == 0U;
            interceptor_unlock();
            if (!retired) return RTGUM_HOST_ERR_BADF;
            return retry_stop ? stop_register_natives_interceptor() : 0L;
        }
        if (rule.handle != handle) {
            interceptor_unlock();
            return RTGUM_HOST_ERR_BADF;
        }
        rule.active = false;
        if (rule.in_flight != 0U) {
            rule.active = true;
            interceptor_unlock();
            return RTGUM_HOST_ERR_BUSY;
        }
        rule.retired_handle = handle;
        rule.handle = 0UL;
        rule.callback = nullptr;
        rule.user_data = nullptr;
        rule.class_name[0] = '\0';
        rule.method_name[0] = '\0';
        rule.signature[0] = '\0';
        stop_jni = active_jni_rules() == 0U;
    }
    interceptor_unlock();
    if (stop_binder) return stop_binder_interceptor();
    if (stop_linker) return stop_linker_interceptor();
    if (stop_lifecycle) return stop_lifecycle_interceptors();
    if (stop_jni) return stop_register_natives_interceptor();
    return 0;
}

long host_binder_interceptor_set_logging(unsigned int enabled)
{
    if (enabled > 1U) return RTGUM_HOST_ERR_INVAL;
    __atomic_store_n(&g_interceptors.binder_logging, enabled != 0U,
                     __ATOMIC_RELEASE);
    return 0;
}

long host_interceptor_query(unsigned int kind, RtGumInterceptorStats *out)
{
    if (!out || out->size < sizeof(RtGumInterceptorStats) ||
        out->version != 1UL)
        return RTGUM_HOST_ERR_INVAL;
    RtGumInterceptorStats result{};
    result.version = 1UL;
    result.size = sizeof(result);
    interceptor_lock();
    if (kind == RTGUM_INTERCEPTOR_BINDER) {
        result.calls = __atomic_load_n(&g_interceptors.binder_calls,
                                       __ATOMIC_RELAXED);
        result.matched = g_interceptors.binder_matched;
        result.callback_errors = __atomic_load_n(
            &g_interceptors.binder_callback_errors, __ATOMIC_RELAXED);
        result.initialized = g_interceptors.binder_ready ? 1U : 0U;
        result.rules = active_binder_rules();
        result.logging_enabled = __atomic_load_n(
            &g_interceptors.binder_logging, __ATOMIC_RELAXED) ? 1U : 0U;
    } else if (kind == RTGUM_INTERCEPTOR_LINKER) {
        result.calls = __atomic_load_n(&g_interceptors.linker_calls,
                                       __ATOMIC_RELAXED);
        result.matched = g_interceptors.linker_matched;
        result.callback_errors = __atomic_load_n(
            &g_interceptors.linker_callback_errors, __ATOMIC_RELAXED);
        result.initialized = g_interceptors.linker_ready ? 1U : 0U;
        result.rules = active_linker_rules();
    } else if (kind == RTGUM_INTERCEPTOR_SO_LIFECYCLE) {
        result.calls = __atomic_load_n(&g_interceptors.lifecycle_calls,
                                       __ATOMIC_RELAXED);
        result.matched = g_interceptors.lifecycle_matched;
        result.callback_errors = __atomic_load_n(
            &g_interceptors.lifecycle_callback_errors, __ATOMIC_RELAXED);
        result.initialized =
            (g_interceptors.constructors_ready && g_interceptors.linker_ready)
                ? 1U : 0U;
        result.rules = active_lifecycle_rules();
    } else if (kind == RTGUM_INTERCEPTOR_JNI_TRACE) {
        result.calls = __atomic_load_n(&g_interceptors.jni_calls,
                                       __ATOMIC_RELAXED);
        result.matched = g_interceptors.jni_matched;
        result.callback_errors = __atomic_load_n(
            &g_interceptors.jni_callback_errors, __ATOMIC_RELAXED);
        result.initialized = g_interceptors.register_natives_ready ? 1U : 0U;
        result.rules = active_jni_rules();
    } else {
        interceptor_unlock();
        return RTGUM_HOST_ERR_INVAL;
    }
    interceptor_unlock();
    *out = result;
    return 0;
}

long release_module_interceptors()
{
    unsigned long handles[kInterceptorRuleCapacity * 4U]{};
    unsigned int count = 0U;
    interceptor_lock();
    for (const BinderRule &rule : g_interceptors.binder_rules)
        if (rule.active) handles[count++] = rule.handle;
    for (const LinkerRule &rule : g_interceptors.linker_rules)
        if (rule.active) handles[count++] = rule.handle;
    for (const LifecycleRule &rule : g_interceptors.lifecycle_rules)
        if (rule.active) handles[count++] = rule.handle;
    for (const JniTraceRule &rule : g_interceptors.jni_rules)
        if (rule.active) handles[count++] = rule.handle;
    interceptor_unlock();
    for (unsigned int index = 0U; index < count; ++index) {
        const long status = host_interceptor_unregister(handles[index]);
        if (status != 0) return status;
    }
    return 0;
}

long release_interceptor_process_state()
{
    const long rules = release_module_interceptors();
    if (rules != 0) return rules;
    long result = stop_binder_interceptor();
    const long onload = stop_jni_onload_hooks();
    if (result == 0) result = onload;
    const long constructors = stop_constructors_interceptor();
    if (result == 0) result = constructors;
    const long jni = stop_register_natives_interceptor();
    if (result == 0) result = jni;
    const long linker = stop_linker_interceptor();
    if (result == 0) result = linker;
    return result;
}

long interceptor_revert_base(unsigned long handle)
{
    if (handle == g_interceptors.binder_hook_handle) {
        interceptor_lock();
        const bool busy = active_binder_rules() != 0U;
        interceptor_unlock();
        return busy ? RTGUM_HOST_ERR_BUSY : stop_binder_interceptor();
    }
    if (handle == g_interceptors.linker_hook_handle) {
        interceptor_lock();
        const bool busy = active_linker_consumers() != 0U;
        interceptor_unlock();
        return busy ? RTGUM_HOST_ERR_BUSY : stop_linker_interceptor();
    }
    if (handle == g_interceptors.constructors_hook_handle) {
        interceptor_lock();
        const bool busy = active_lifecycle_rules() != 0U;
        interceptor_unlock();
        return busy ? RTGUM_HOST_ERR_BUSY : stop_constructors_interceptor();
    }
    if (handle == g_interceptors.register_natives_hook_handle) {
        interceptor_lock();
        const bool busy = active_jni_rules() != 0U;
        interceptor_unlock();
        return busy ? RTGUM_HOST_ERR_BUSY
                    : stop_register_natives_interceptor();
    }
    return RTGUM_HOST_ERR_NOENT;
}

long host_hook_binder(unsigned long *out_handle)
{
    if (!out_handle) return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0UL;
    const long result = ensure_binder_interceptor();
    if (result == 0) *out_handle = g_interceptors.binder_hook_handle;
    return result;
}

long host_lua_eval(const char *script, char *error, unsigned long error_capacity)
{
    const long loaded = ensure_lua_backend();
    if (loaded != 0) return loaded;
    if (!g_host_api.lua_eval || g_host_api.lua_eval == &host_lua_eval)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_host_api.lua_eval(script, error, error_capacity);
}

long host_lua_eval_async(const char *script, char *error,
                         unsigned long error_capacity)
{
    const long loaded = ensure_lua_backend();
    if (loaded != 0) return loaded;
    if ((g_host_api.capabilities & RTGUM_HOST_CAP_LUA_ASYNC) == 0UL ||
        !g_host_api.lua_eval_async ||
        g_host_api.lua_eval_async == &host_lua_eval_async)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_host_api.lua_eval_async(script, error, error_capacity);
}

long host_lua_stop()
{
    if (g_lua_state != 1) return 0;
    if (!g_host_api.lua_stop || g_host_api.lua_stop == &host_lua_stop)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_host_api.lua_stop();
}

long host_java_replace(void *env,
                       void *reflected_method,
                       void *hooker_object,
                       void *callback_method,
                       unsigned long *out_handle)
{
    const long loaded = ensure_java_backend();
    if (loaded != 0) return loaded;
    if (!g_host_api.hook_java_replace || g_host_api.hook_java_replace == &host_java_replace)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_host_api.hook_java_replace(env, reflected_method, hooker_object, callback_method,
                                        out_handle);
}

long host_java_revert(unsigned long handle)
{
    const long loaded = ensure_java_backend();
    if (loaded != 0) return loaded;
    if (!g_host_api.hook_java_revert || g_host_api.hook_java_revert == &host_java_revert)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_host_api.hook_java_revert(handle);
}

long host_java_method(void *env,
                      const char *jni_class,
                      const char *name,
                      const char *signature,
                      unsigned long *out_handle)
{
    const long loaded = ensure_java_backend();
    if (loaded != 0) return loaded;
    if (!g_host_api.hook_java_method || g_host_api.hook_java_method == &host_java_method)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_host_api.hook_java_method(env, jni_class, name, signature, out_handle);
}

/* ============ Mako ART hook backend (lazy ghost load) ============ */

long api_ghost_alloc(unsigned long size, unsigned int protection,
                     unsigned long *out_address);
long api_ghost_free(unsigned long address);

long mako_api_log(const char *text)
{
    return api_log(text);
}

long api_ghost_protect(unsigned long address, unsigned int protection);

long mako_api_ghost_alloc(unsigned long size, unsigned int protection,
                          unsigned long *out_address)
{
    return api_ghost_alloc(size, protection, out_address);
}

long mako_api_ghost_free(unsigned long address)
{
    return api_ghost_free(address);
}

long mako_api_ghost_protect(unsigned long address, unsigned int protection)
{
    return api_ghost_protect(address, protection);
}

long mako_api_ghost_code_write(unsigned long address, const void *bytes,
                               unsigned long length)
{
    if (address == 0UL || bytes == nullptr || length == 0UL ||
        length > RTGUM_GHOST_CODE_WRITE_MAX ||
        address + length < address)
        return RTGUM_HOST_ERR_INVAL;
    RtGumGhostCodeWriteRequest request{};
    request.target = address;
    request.source = reinterpret_cast<unsigned long>(bytes);
    request.length = length;
    return daemon_syscall(RTGUM_DAEMON_OP_GHOST_CODE_WRITE,
                          reinterpret_cast<unsigned long>(&request));
}

long mako_api_art_register(unsigned long page, unsigned long *out_handle)
{
    if (out_handle != nullptr) *out_handle = 0;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) = page;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) = 0;
    long result = daemon_syscall(RTGUM_DAEMON_OP_ART_PAGE_REGISTER, 0);
    if (result == -16) result = 0; /* EBUSY: page already shadowed; share it */
    if (result == 0 && out_handle != nullptr) *out_handle = page;
    return result;
}

long mako_api_art_unregister(unsigned long page)
{
    return daemon_syscall(RTGUM_DAEMON_OP_ART_PAGE_UNREGISTER, page);
}

long mako_api_art_patch(unsigned long page, unsigned long offset,
                        unsigned long value)
{
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) = page;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) = offset;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 16UL) = value;
    return daemon_syscall(RTGUM_DAEMON_OP_ART_PAGE_PATCH, 0);
}

long mako_api_art_unpatch(unsigned long page, unsigned long offset)
{
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) = page;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) = offset;
    return daemon_syscall(RTGUM_DAEMON_OP_ART_PAGE_UNPATCH, 0);
}

long mako_api_art_read(unsigned long page, unsigned long offset,
                       unsigned long *out_value)
{
    if (out_value != nullptr) *out_value = 0;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) = page;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) = offset;
    const long result = daemon_syscall(RTGUM_DAEMON_OP_ART_PAGE_READ, 0);
    if (result == 0 && out_value != nullptr)
        *out_value = load_u64(reinterpret_cast<const void *>(
            g_ctx_va + RTGUM_CTX_PAYLOAD));
    return result;
}

long mako_api_art_trust_add(unsigned long start, unsigned long end)
{
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) = start;
    *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) = end;
    return daemon_syscall(RTGUM_DAEMON_OP_ART_TRUST_ADD, 0);
}

long mako_api_art_trust_clear()
{
    return daemon_syscall(RTGUM_DAEMON_OP_ART_TRUST_CLEAR, 0);
}

long mako_api_art_shadow_query()
{
    return daemon_syscall(RTGUM_DAEMON_OP_ART_SHADOW_QUERY, 0);
}

long mako_api_find_export(const char *soname,
                          const char *symbol,
                          unsigned long *out_address)
{
    return host_find_export(soname, symbol, out_address);
}

void build_mako_host()
{
    memset(&g_mako_host, 0, sizeof(g_mako_host));
    g_mako_host.version = MAKO_HOST_API_VERSION;
    g_mako_host.size = sizeof(g_mako_host);
    g_mako_host.log = mako_api_log;
    g_mako_host.ghost_alloc = mako_api_ghost_alloc;
    g_mako_host.ghost_free = mako_api_ghost_free;
    g_mako_host.ghost_protect = mako_api_ghost_protect;
    g_mako_host.ghost_code_write = mako_api_ghost_code_write;
    g_mako_host.art_page_register = mako_api_art_register;
    g_mako_host.art_page_unregister = mako_api_art_unregister;
    g_mako_host.art_page_patch = mako_api_art_patch;
    g_mako_host.art_page_unpatch = mako_api_art_unpatch;
    g_mako_host.art_page_read = mako_api_art_read;
    g_mako_host.art_trust_add = mako_api_art_trust_add;
    g_mako_host.art_trust_clear = mako_api_art_trust_clear;
    g_mako_host.art_shadow_query = mako_api_art_shadow_query;
    g_mako_host.find_export = mako_api_find_export;
    g_mako_host.reflection =
        __atomic_load_n(&g_mako_reflection_ready, __ATOMIC_ACQUIRE)
            ? &g_mako_reflection
            : nullptr;
}

/* Lazy load: the Daemon links libmako-ghost.so from the KPM cache only when a
 * module first calls an artHook entry point. The Manager switch pushed the
 * path into the KPM cache at config time. */
long ensure_mako_backend()
{
    if (!g_mako_enabled) {
        api_log("rtgum-stage2-daemon: mako disabled by package config");
        /* This is a final configuration decision, not a class-loader race.
         * Returning NOENT makes modules retry an explicitly disabled backend
         * and can keep their deferred worker alive for tens of seconds. */
        return RTGUM_HOST_ERR_NOTSUP;
    }
    if (g_mako_state == 1) return 0;
    if (g_mako_path[0] == '\0') {
        api_log("rtgum-stage2-daemon: mako path not configured");
        return RTGUM_HOST_ERR_NOTSUP;
    }
    unsigned long base = 0;
    unsigned long entry = 0;
    unsigned long size = 0;
    const long loaded =
        load_ghost_image(g_mako_path, "rtgum_mako_entry", &base, &entry, &size);
    if (loaded != 0 || base == 0 || entry == 0) {
        api_log("rtgum-stage2-daemon: mako ghost load failed");
        return loaded != 0 ? loaded : RTGUM_HOST_ERR_NOENT;
    }
    build_mako_host();
    memset(&g_mako_hooks, 0, sizeof(g_mako_hooks));
    reinterpret_cast<MakoEntry>(entry)(&g_mako_host, &g_mako_hooks);
    if (g_mako_hooks.version != MAKO_HOOK_API_VERSION ||
        g_mako_hooks.size < sizeof(MakoHookApi) ||
        g_mako_hooks.hook_method == nullptr ||
        g_mako_hooks.hook_reflected == nullptr ||
        g_mako_hooks.revert == nullptr) {
        api_log("rtgum-stage2-daemon: mako bind failed");
        return RTGUM_HOST_ERR_NXIO;
    }
    g_mako_base = base;
    g_mako_state = 1;
    api_log("rtgum-stage2-daemon: mako backend bound");
    return 0;
}

bool track_mako_handle(unsigned long handle)
{
    if (handle == 0) return false;
    for (unsigned int index = 0; index < kMakoHandleCapacity; ++index) {
        unsigned long empty = 0;
        if (__atomic_compare_exchange_n(&g_mako_handles[index], &empty, handle,
                                        false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
            return true;
    }
    return false;
}

void forget_mako_handle(unsigned long handle)
{
    for (unsigned int index = 0; index < kMakoHandleCapacity; ++index) {
        unsigned long expected = handle;
        if (__atomic_compare_exchange_n(&g_mako_handles[index], &expected, 0UL,
                                        false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
            return;
    }
}

long publish_mako_handle(long status, unsigned long handle,
                         unsigned long *out_handle)
{
    if (status != 0) return status;
    if (handle == 0) return RTGUM_HOST_ERR_NXIO;
    if (!track_mako_handle(handle)) {
        (void)g_mako_hooks.revert(handle);
        return RTGUM_HOST_ERR_BUSY;
    }
    *out_handle = handle;
    return 0;
}

long revert_tracked_mako_hooks()
{
    if (g_mako_state != 1 || g_mako_hooks.revert == nullptr) return 0;
    long first_error = 0;
    for (unsigned int index = 0; index < kMakoHandleCapacity; ++index) {
        const unsigned long handle =
            __atomic_load_n(&g_mako_handles[index], __ATOMIC_ACQUIRE);
        if (handle == 0) continue;
        const long status = g_mako_hooks.revert(handle);
        if (status == 0) {
            unsigned long expected = handle;
            (void)__atomic_compare_exchange_n(&g_mako_handles[index], &expected,
                                              0UL, false, __ATOMIC_ACQ_REL,
                                              __ATOMIC_ACQUIRE);
        } else if (first_error == 0) {
            first_error = status;
        }
    }
    return first_error;
}

long host_art_hook_method(void *env,
                          const char *jni_class,
                          const char *name,
                          const char *signature,
                          void (*on_enter)(void *, void *),
                          void (*on_leave)(void *, void *),
                          void *user_data,
                          unsigned long *out_handle)
{
    if (out_handle == nullptr) return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0;
    if (__atomic_load_n(&g_module_unloading, __ATOMIC_ACQUIRE) != 0U)
        return RTGUM_HOST_ERR_BUSY;
    const long loaded = ensure_mako_backend();
    if (loaded != 0) return loaded;
    unsigned long handle = 0;
    const long status = g_mako_hooks.hook_method(
        env, jni_class, name, signature, 0, on_enter, on_leave, user_data,
        &handle);
    return publish_mako_handle(status, handle, out_handle);
}

long host_art_hook_method_ex(void *env,
                             const char *jni_class,
                             const char *name,
                             const char *signature,
                             unsigned int flags,
                             void (*on_enter)(void *, void *),
                             void (*on_leave)(void *, void *),
                             void *user_data,
                             unsigned long *out_handle)
{
    if (out_handle == nullptr) return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0;
    if ((flags & ~RTGUM_ART_METHOD_STATIC) != 0U)
        return RTGUM_HOST_ERR_INVAL;
    if (__atomic_load_n(&g_module_unloading, __ATOMIC_ACQUIRE) != 0U)
        return RTGUM_HOST_ERR_BUSY;
    const long loaded = ensure_mako_backend();
    if (loaded != 0) return loaded;
    unsigned long handle = 0;
    const long status = g_mako_hooks.hook_method(
        env, jni_class, name, signature,
        (flags & RTGUM_ART_METHOD_STATIC) != 0U ? 1 : 0,
        on_enter, on_leave, user_data, &handle);
    return publish_mako_handle(status, handle, out_handle);
}

long host_art_hook_reflected(void *env,
                             void *method_object,
                             void (*on_enter)(void *, void *),
                             void (*on_leave)(void *, void *),
                             void *user_data,
                             unsigned long *out_handle)
{
    if (out_handle == nullptr) return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0;
    if (__atomic_load_n(&g_module_unloading, __ATOMIC_ACQUIRE) != 0U)
        return RTGUM_HOST_ERR_BUSY;
    const long loaded = ensure_mako_backend();
    if (loaded != 0) return loaded;
    unsigned long handle = 0;
    const long status = g_mako_hooks.hook_reflected(
        env, method_object, on_enter, on_leave, user_data, &handle);
    return publish_mako_handle(status, handle, out_handle);
}

long host_art_hook_activity_create(void *env,
                                   const char *jni_class,
                                   void (*on_enter)(void *, void *),
                                   void (*on_leave)(void *, void *),
                                   void *user_data,
                                   unsigned long *out_handle)
{
    if (out_handle == nullptr) return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0;
    if (__atomic_load_n(&g_module_unloading, __ATOMIC_ACQUIRE) != 0U)
        return RTGUM_HOST_ERR_BUSY;
    const long loaded = ensure_mako_backend();
    if (loaded != 0) return loaded;
    if (g_mako_hooks.hook_activity_create == nullptr)
        return RTGUM_HOST_ERR_NOTSUP;
    unsigned long handle = 0;
    const long status = g_mako_hooks.hook_activity_create(
        env, jni_class, on_enter, on_leave, user_data, &handle);
    return publish_mako_handle(status, handle, out_handle);
}

long host_art_hook_revert(unsigned long handle)
{
    if (g_mako_state != 1) return RTGUM_HOST_ERR_NOTSUP;
    const long status = g_mako_hooks.revert(handle);
    if (status == 0) forget_mako_handle(handle);
    return status;
}

long host_art_hook_status(unsigned long handle, unsigned int *out_state)
{
    if (g_mako_state != 1) return RTGUM_HOST_ERR_NOTSUP;
    return g_mako_hooks.status(handle, out_state);
}

/* ============ Gum backend (VMA-less private linker) ============ */

constexpr unsigned long kGhostAllocatorChunk = 512UL * 1024UL;

long host_gum_ghost_alloc(unsigned long size, unsigned int protection,
                          unsigned long *out_address)
{
    const long allocated = api_ghost_alloc(size, protection, out_address);
    if (allocated != 0 || !out_address) return allocated;
    const unsigned long span_size =
        (size + kDexPageSize - 1UL) & ~(kDexPageSize - 1UL);
    const long policy = api_ghost_fork_policy(*out_address, span_size, true);
    if (policy == 0) return 0;
    (void)api_ghost_free(*out_address);
    *out_address = 0UL;
    return policy;
}

long host_gum_ghost_alloc_span(unsigned long size,
                               unsigned int protection,
                               unsigned long *out_address,
                               unsigned long *out_span_size)
{
    const long allocated = api_ghost_alloc_span(
        size, protection, out_address, out_span_size);
    if (allocated != 0 || !out_address || !out_span_size) return allocated;
    const long policy = api_ghost_fork_policy(
        *out_address, *out_span_size, true);
    if (policy == 0) return 0;
    (void)api_ghost_free_span(*out_address, *out_span_size);
    *out_address = 0UL;
    *out_span_size = 0UL;
    return policy;
}

long host_gum_ghost_alloc_near_span(unsigned long size,
                                    unsigned long alignment,
                                    unsigned int protection,
                                    unsigned long near_address,
                                    unsigned long max_distance,
                                    unsigned long *out_address,
                                    unsigned long *out_span_size)
{
    const long allocated = api_ghost_alloc_near_span(
        size, alignment, protection, near_address, max_distance,
        out_address, out_span_size);
    if (allocated != 0 || !out_address || !out_span_size) return allocated;
    const long policy = api_ghost_fork_policy(
        *out_address, *out_span_size, true);
    if (policy == 0) return 0;
    (void)api_ghost_free_span(*out_address, *out_span_size);
    *out_address = 0UL;
    *out_span_size = 0UL;
    return policy;
}

long host_gum_ghost_protect_span(unsigned long address,
                                 unsigned long span_size,
                                 unsigned int protection)
{
    if (address == 0UL || (address & 0xfffUL) != 0UL || span_size == 0UL ||
        span_size > kDexMaximumBytes || (span_size & 0xfffUL) != 0UL ||
        protection > 7U)
        return RTGUM_HOST_ERR_INVAL;
    /* allocate_image() owns one mapping per <=512 KiB chunk.  Protection is
     * changed per ownership record; never issue mprotect(2) on a VMA-less VA. */
    for (unsigned long offset = 0; offset < span_size;
         offset += kGhostAllocatorChunk) {
        const long status = api_ghost_protect(address + offset, protection);
        if (status != 0) return status;
    }
    return 0;
}

long host_gum_ghost_free_span(unsigned long address, unsigned long span_size)
{
    return api_ghost_free_span(address, span_size);
}

long host_gum_code_read_clean(unsigned long address, void *buffer,
                              unsigned long length)
{
    if (address == 0UL || buffer == nullptr || length == 0UL ||
        length > kDexPageSize || address + length < address)
        return RTGUM_HOST_ERR_INVAL;
    /* MEMORY_READ writes through GUP, which cannot target our VMA-less
     * backend buffer.  Bounce through the Daemon stack while the KPM's
     * follow_page_pte hook selects the clean PFN for shadowed source pages. */
    unsigned char scratch[256]{};
    auto *output = static_cast<unsigned char *>(buffer);
    unsigned long copied = 0UL;
    while (copied < length) {
        unsigned long amount = length - copied;
        if (amount > sizeof(scratch)) amount = sizeof(scratch);
        const long status = resolver_memory_read(address + copied, scratch,
                                                 amount);
        if (status != 0) return status;
        for (unsigned long index = 0UL; index < amount; ++index)
            output[copied + index] = scratch[index];
        copied += amount;
    }
    return 0;
}

long host_gum_ghost_code_write(unsigned long address, const void *bytes,
                               unsigned long length)
{
    if (address == 0UL || bytes == nullptr || length == 0UL ||
        address + length < address)
        return RTGUM_HOST_ERR_INVAL;
    const auto *source = static_cast<const unsigned char *>(bytes);
    unsigned long written = 0UL;
    while (written < length) {
        unsigned long amount = length - written;
        if (amount > RTGUM_GHOST_CODE_WRITE_MAX)
            amount = RTGUM_GHOST_CODE_WRITE_MAX;
        const long status = mako_api_ghost_code_write(
            address + written, source + written, amount);
        if (status != 0) return status;
        written += amount;
    }
    return 0;
}

long host_gum_shadow_code_patch(unsigned long address, const void *bytes,
                                unsigned long length)
{
    return shadow_kernel_patch(address,
                               static_cast<const unsigned char *>(bytes),
                               length, true /* fork propagation */);
}

long host_gum_shadow_code_unpatch(unsigned long address,
                                  unsigned long length)
{
    return shadow_kernel_unpatch(address, length);
}

void build_gum_host()
{
    memset(&g_gum_host, 0, sizeof(g_gum_host));
    g_gum_host.version = RTGUM_GUM_API_VERSION;
    g_gum_host.reserved = RTGUM_GUM_HOST_GHOST_MEMORY;
    g_gum_host.log = mako_api_log;
    g_gum_host.ghost_alloc = host_gum_ghost_alloc;
    g_gum_host.ghost_free = api_ghost_free;
    g_gum_host.ghost_protect = api_ghost_protect;
    g_gum_host.sleep_ms = host_sleep_ms;
    g_gum_host.ghost_alloc_span = host_gum_ghost_alloc_span;
    g_gum_host.ghost_protect_span = host_gum_ghost_protect_span;
    g_gum_host.ghost_free_span = host_gum_ghost_free_span;
    g_gum_host.ghost_alloc_near_span = host_gum_ghost_alloc_near_span;
    g_gum_host.code_read_clean = host_gum_code_read_clean;
    g_gum_host.ghost_code_write = host_gum_ghost_code_write;
    g_gum_host.shadow_code_patch = host_gum_shadow_code_patch;
    g_gum_host.shadow_code_unpatch = host_gum_shadow_code_unpatch;
    g_gum_host.find_export = resolver_find_export;
    g_gum_host.memory_read = resolver_memory_read;
    g_gum_host.memory_write = resolver_memory_write;
}

/* Lazy load from the KPM's config-time byte cache.  The platform linker never
 * sees this image, so it has no VMA, link_map entry, or dl_iterate_phdr node. */
long ensure_gum_backend()
{
    if (g_gum_state == 1) return 0;
    if (g_gum_state < 0) return g_gum_state;
    if (g_gum_path[0] == '\0') {
        api_log("rtgum-stage2-daemon: gum path not configured");
        return RTGUM_HOST_ERR_NOENT;
    }
    unsigned long base = 0;
    unsigned long entry_address = 0;
    unsigned long size = 0;
    const long loaded = load_ghost_image(g_gum_path, "rtgum_gum_entry",
                                         &base, &entry_address, &size);
    if (loaded != 0 || base == 0 || entry_address == 0 || size == 0) {
        g_gum_state = loaded == RTGUM_HOST_ERR_AGAIN
                          ? 0
                          : (loaded != 0 ? loaded : RTGUM_HOST_ERR_NOENT);
        api_log("rtgum-stage2-daemon: gum ghost load failed");
        return g_gum_state;
    }
    using GumEntryFn = long (*)(const RtGumHost *, RtGumApi *);
    auto *entry = reinterpret_cast<GumEntryFn>(entry_address);
    build_gum_host();
    memset(&g_gum_api, 0, sizeof(g_gum_api));
    const long bound = entry(&g_gum_host, &g_gum_api);
    if (bound != 0 || g_gum_api.version != RTGUM_GUM_API_VERSION ||
        g_gum_api.intercept_attach == nullptr || g_gum_api.find_export == nullptr ||
        g_gum_api.intercept_attach_address == nullptr ||
        g_gum_api.intercept_revert == nullptr ||
        g_gum_api.replace == nullptr || g_gum_api.memory_read == nullptr ||
        g_gum_api.memory_write == nullptr || g_gum_api.memory_alloc == nullptr ||
        g_gum_api.memory_free == nullptr || g_gum_api.stalker_start == nullptr ||
        g_gum_api.stalker_invalidate == nullptr ||
        g_gum_api.stalker_stop == nullptr ||
        g_gum_api.trace_start == nullptr || g_gum_api.trace_stop == nullptr ||
        g_gum_api.trace_query == nullptr) {
        /* gum_init_embedded() may already have created workers.  Keep the
         * failed image mapped until process teardown instead of unmapping code
         * that a worker could still execute.  The latched error prevents a
         * second image from being loaded over it. */
        api_log("rtgum-stage2-daemon: gum bind failed");
        g_gum_base = base;
        g_gum_size = size;
        g_gum_state = bound != 0 ? bound : RTGUM_HOST_ERR_NXIO;
        return g_gum_state;
    }
    g_gum_base = base;
    g_gum_size = size;
    g_gum_state = 1;
    api_status(RTGUM_DAEMON_STATUS_GUM_BASE, base);
    if (g_status_va != 0) {
        auto *flags = reinterpret_cast<unsigned long *>(
            g_status_va + RTGUM_DAEMON_STATUS_BACKEND_FLAGS * 8UL);
        __atomic_fetch_or(flags,
                          RTGUM_DAEMON_BACKEND_GUM_GHOST |
                              RTGUM_DAEMON_BACKEND_GUM_ALLOCATIONS_GHOST,
                          __ATOMIC_RELEASE);
    }
    api_log("rtgum-stage2-daemon: gum ghost backend bound");
    return 0;
}

long host_gum_find_export(const char *soname, const char *symbol, unsigned long *out_address)
{
    return host_find_export(soname, symbol, out_address);
}

long host_gum_intercept_attach(const char *soname,
                               const char *symbol,
                               void (*on_enter)(RtGumInvocation *invocation,
                                                void *user_data),
                               void (*on_leave)(RtGumInvocation *invocation,
                                                void *user_data),
                               void *user_data,
                               unsigned long *out_handle)
{
    api_log("rtgum-stage2-daemon: gum attach backend begin");
    const long loaded = ensure_gum_backend();
    if (loaded != 0) {
        api_log("rtgum-stage2-daemon: gum attach backend failed");
        return loaded;
    }
    api_log("rtgum-stage2-daemon: gum attach resolve begin");
    unsigned long address = 0;
    const long found = host_find_export(soname, symbol, &address);
    if (found != 0) {
        api_log("rtgum-stage2-daemon: gum attach resolve failed");
        return found;
    }
    if (address == 0) {
        api_log("rtgum-stage2-daemon: gum attach resolve zero");
        return RTGUM_HOST_ERR_NOENT;
    }
    api_log("rtgum-stage2-daemon: gum attach interceptor begin");
    const long attached = g_gum_api.intercept_attach_address(address,
                                                             on_enter,
                                                             on_leave,
                                                             user_data,
                                                             out_handle);
    api_log(attached == 0
                ? "rtgum-stage2-daemon: gum attach interceptor done"
                : "rtgum-stage2-daemon: gum attach interceptor failed");
    return attached;
}

long host_gum_intercept_attach_address(unsigned long address,
                                       void (*on_enter)(RtGumInvocation *invocation,
                                                        void *user_data),
                                       void (*on_leave)(RtGumInvocation *invocation,
                                                        void *user_data),
                                       void *user_data,
                                       unsigned long *out_handle)
{
    const long loaded = ensure_gum_backend();
    if (loaded != 0) return loaded;
    return g_gum_api.intercept_attach_address(address,
                                              on_enter,
                                              on_leave,
                                              user_data,
                                              out_handle);
}

long host_gum_intercept_revert(unsigned long handle)
{
    if (g_gum_state != 1) return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.intercept_revert(handle);
}

long host_gum_replace(unsigned long target,
                      unsigned long replacement,
                      unsigned long *out_original,
                      unsigned long *out_handle)
{
    const long loaded = ensure_gum_backend();
    if (loaded != 0) return loaded;
    return g_gum_api.replace(target, replacement, out_original, out_handle);
}

long host_gum_memory_read(unsigned long address, void *buffer, unsigned long length)
{
    const long loaded = ensure_gum_backend();
    if (loaded != 0) return loaded;
    if (g_gum_api.memory_read == nullptr) return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.memory_read(address, buffer, length);
}

long host_gum_memory_write(unsigned long address,
                           const void *buffer,
                           unsigned long length)
{
    const long loaded = ensure_gum_backend();
    if (loaded != 0) return loaded;
    if (g_gum_api.memory_write == nullptr) return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.memory_write(address, buffer, length);
}

long host_gum_memory_alloc(unsigned long size, unsigned long *out_address)
{
    const long loaded = ensure_gum_backend();
    if (loaded != 0) return loaded;
    return g_gum_api.memory_alloc(size, out_address);
}

long host_gum_memory_free(unsigned long address)
{
    if (g_gum_state != 1) return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.memory_free(address);
}

long host_dbi_stalker_start(RtGumStalkerStats *stats,
                            unsigned long watched_start,
                            unsigned long watched_size)
{
    const long loaded = ensure_gum_backend();
    if (loaded != 0) return loaded;
    if (!g_gum_api.stalker_start) return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.stalker_start(stats, watched_start, watched_size);
}

long host_dbi_stalker_invalidate(unsigned long address)
{
    if (g_gum_state != 1 || !g_gum_api.stalker_invalidate)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.stalker_invalidate(address);
}

long host_dbi_stalker_stop()
{
    if (g_gum_state != 1 || !g_gum_api.stalker_stop)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.stalker_stop();
}

long host_trace_start(const RtGumTraceConfig *config,
                      unsigned long *out_handle)
{
    const long loaded = ensure_gum_backend();
    if (loaded != 0) return loaded;
    if (!g_gum_api.trace_start) return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.trace_start(config, out_handle);
}

long host_trace_stop(unsigned long handle)
{
    if (g_gum_state != 1 || !g_gum_api.trace_stop)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.trace_stop(handle);
}

long host_trace_query(unsigned long handle, RtGumTraceStats *out_stats)
{
    if (g_gum_state != 1 || !g_gum_api.trace_query)
        return RTGUM_HOST_ERR_NOTSUP;
    return g_gum_api.trace_query(handle, out_stats);
}

long api_log(const char *text)
{
    return daemon_syscall(RTGUM_DAEMON_OP_LOG, reinterpret_cast<unsigned long>(text));
}

long api_cmdline_at(unsigned long ctx_va, char *out, unsigned long capacity)
{
    (void)ctx_va;
    if (!out || capacity < 256UL) return -1;
    /* Procfs cmdline rejected kernel_read on Pixel 8. The Daemon can read its
     * own proc entry directly in EL0 without a kernel-to-user stack copy. */
    const long descriptor = user_syscall(
        56, -100, reinterpret_cast<long>("/proc/self/cmdline"), 0x80000);
    if (descriptor < 0) return descriptor;
    const long count = user_syscall(63, descriptor,
                                    reinterpret_cast<long>(out),
                                    static_cast<long>(capacity - 1UL));
    user_syscall(57, descriptor, 0, 0);
    if (count <= 0) return count < 0 ? count : -1;
    out[count] = '\0';
    const unsigned long length = ghost_length(out, static_cast<unsigned long>(count));
    return length < static_cast<unsigned long>(count)
               ? static_cast<long>(length)
               : -1;
}

long api_cmdline(char *out, unsigned long capacity)
{
    return api_cmdline_at(g_ctx_va, out, capacity);
}

long api_status(unsigned int index, unsigned long value)
{
    if (!g_status_va || index >= 8U) return -1;
    *reinterpret_cast<volatile unsigned long *>(g_status_va + index * 8UL) = value;
    return 0;
}

void api_exit(int code)
{
    register long x0 asm("x0") = code;
    register long x8 asm("x8") = 93;
    asm volatile("svc #0" ::"r"(x0), "r"(x8));
    __builtin_unreachable();
}

long api_ghost_alloc(unsigned long size, unsigned int protection, unsigned long *out_address)
{
    if (!out_address || protection > 7U || (protection & 3U) == 0U) return -1;
    const long address = daemon_syscall(RTGUM_DAEMON_OP_GHOST_ALLOC,
                                        (size << 3UL) | protection);
    if (address <= 0) return address;
    *out_address = static_cast<unsigned long>(address);
    return 0;
}

long api_ghost_protect(unsigned long address, unsigned int protection)
{
    if (address == 0UL || (address & 0xFFFUL) != 0UL || protection > 7U)
        return RTGUM_HOST_ERR_INVAL;
    return daemon_syscall(RTGUM_DAEMON_OP_GHOST_PROTECT,
                          address | (static_cast<unsigned long>(protection) & 7UL));
}

long api_ghost_free(unsigned long address)
{
    return daemon_syscall(RTGUM_DAEMON_OP_GHOST_FREE, address);
}

long api_ghost_alloc_span(unsigned long size,
                          unsigned int protection,
                          unsigned long *out_address,
                          unsigned long *out_span_size)
{
    if (!out_address || !out_span_size || size == 0UL ||
        size > kDexMaximumBytes || protection > 7U ||
        (protection & 3U) == 0U)
        return RTGUM_HOST_ERR_INVAL;
    const unsigned long span_size =
        (size + kDexPageSize - 1UL) & ~(kDexPageSize - 1UL);
    const long address = daemon_syscall(RTGUM_DAEMON_OP_GHOST_ALLOC_SPAN,
                                        (size << 3UL) | protection);
    if (address <= 0) return address;
    *out_address = static_cast<unsigned long>(address);
    *out_span_size = span_size;
    return 0;
}

long api_ghost_alloc_near_span(unsigned long size,
                               unsigned long alignment,
                               unsigned int protection,
                               unsigned long near_address,
                               unsigned long max_distance,
                               unsigned long *out_address,
                               unsigned long *out_span_size)
{
    if (!out_address || !out_span_size || size == 0UL ||
        size > kDexMaximumBytes || alignment < kDexPageSize ||
        (alignment & (alignment - 1UL)) != 0UL ||
        protection > 7U || (protection & 3U) == 0U ||
        near_address < kDexPageSize || max_distance < size)
        return RTGUM_HOST_ERR_INVAL;
    RtGumGhostAllocNearRequest request{};
    request.size = size;
    request.alignment = alignment;
    request.protection = protection;
    request.near_address = near_address;
    request.max_distance = max_distance;
    const long address = daemon_syscall(
        RTGUM_DAEMON_OP_GHOST_ALLOC_NEAR_SPAN,
        reinterpret_cast<unsigned long>(&request));
    if (address <= 0) return address;
    const unsigned long span_size =
        (size + kDexPageSize - 1UL) & ~(kDexPageSize - 1UL);
    *out_address = static_cast<unsigned long>(address);
    *out_span_size = span_size;
    return 0;
}

long api_ghost_fork_policy(unsigned long address, unsigned long span_size,
                           bool propagate)
{
    if (address == 0UL || (address & (kDexPageSize - 1UL)) != 0UL ||
        span_size == 0UL || span_size > kDexMaximumBytes ||
        (span_size & (kDexPageSize - 1UL)) != 0UL)
        return RTGUM_HOST_ERR_INVAL;
    RtGumGhostForkPolicyRequest request{};
    request.address = address;
    request.span_size = span_size;
    request.propagate = propagate ? 1UL : 0UL;
    return daemon_syscall(RTGUM_DAEMON_OP_GHOST_FORK_POLICY,
                          reinterpret_cast<unsigned long>(&request));
}

long api_module_fork_policy(unsigned long base, bool propagate)
{
    if (base == 0UL || (base & (kDexPageSize - 1UL)) != 0UL)
        return RTGUM_HOST_ERR_INVAL;
    return daemon_syscall(RTGUM_DAEMON_OP_MODULE_FORK_POLICY,
                          base | (propagate ? 1UL : 0UL));
}

long api_ghost_free_span(unsigned long address, unsigned long span_size)
{
    if (address == 0UL || (address & (kDexPageSize - 1UL)) != 0UL ||
        span_size == 0UL || span_size > kDexMaximumBytes ||
        (span_size & (kDexPageSize - 1UL)) != 0UL)
        return RTGUM_HOST_ERR_INVAL;
    const unsigned long pages = span_size / kDexPageSize;
    if (pages == 0UL || pages > kDexPageSize) return RTGUM_HOST_ERR_INVAL;
    return daemon_syscall(RTGUM_DAEMON_OP_GHOST_FREE_SPAN,
                          address | (pages - 1UL));
}

long resolver_cache_alloc(unsigned long size, unsigned long *out_address)
{
    return api_ghost_alloc(size, 3U /* Read | Write */, out_address);
}

long resolver_cache_free(unsigned long address)
{
    return api_ghost_free(address);
}

long api_module_unload(unsigned long base)
{
    char path[160];
    unsigned long mapped_size = 0;
    const bool registered =
        g_symbol_resolver.TakeGhost(base, path, sizeof(path), mapped_size);
    const long status = daemon_syscall(RTGUM_DAEMON_OP_MODULE_UNLINK, base);
    if (status != 0 && registered)
        (void)g_symbol_resolver.RegisterGhost(path, base, mapped_size);
    return status;
}

long release_active_module()
{
    if (g_module_base == 0) return 0;
    __atomic_store_n(&g_module_unloading, 1U, __ATOMIC_RELEASE);
    if (active_module_job_running()) {
        __atomic_store_n(&g_module_unloading, 0U, __ATOMIC_RELEASE);
        return RTGUM_HOST_ERR_BUSY;
    }
    if (g_module_unload_entry != 0) {
        const unsigned long callback = g_module_unload_entry;
        g_module_unload_entry = 0;
        reinterpret_cast<GhostModuleUnload>(callback)(&g_api);
    }
    /* Modules should revert the handles they own. Sweep the Daemon registry as
     * a hard teardown guarantee so an incomplete module cannot leave an
     * ArtMethod pointing at its callbacks after the .ghm is unmapped. */
    const long hook_status = revert_tracked_mako_hooks();
    if (hook_status != 0) {
        __atomic_store_n(&g_module_unloading, 0U, __ATOMIC_RELEASE);
        return hook_status;
    }
    /* A module is expected to unload the handles it owns. Sweep anything it
     * forgot before unmapping the .ghm so no ClassLoader/global ref/ghost span
     * can outlive its owner indefinitely. */
    const long dex_status = release_all_dex_loaders();
    if (dex_status != 0) {
        __atomic_store_n(&g_module_unloading, 0U, __ATOMIC_RELEASE);
        return dex_status;
    }
    const long interceptor_status = release_module_interceptors();
    if (interceptor_status != 0) {
        __atomic_store_n(&g_module_unloading, 0U, __ATOMIC_RELEASE);
        return interceptor_status;
    }
    const long result = api_module_unload(g_module_base);
    if (result != 0) {
        __atomic_store_n(&g_module_unloading, 0U, __ATOMIC_RELEASE);
        return result;
    }
    g_module_base = 0;
    g_module_size = 0;
    api_status(RTGUM_DAEMON_STATUS_MODULE_BASE, 0);
    api_status(RTGUM_DAEMON_STATUS_MODULES, 0);
    __atomic_store_n(&g_module_unloading, 0U, __ATOMIC_RELEASE);
    return 0;
}

/* The KPM writes string replies into the bootstrap context payload area. */
char *ctx_reply()
{
    return reinterpret_cast<char *>(g_ctx_va + RTGUM_CTX_PAYLOAD);
}

bool scan_hex(const char *text, unsigned long &value)
{
    if (!text || text[0] != '0' || (text[1] != 'x' && text[1] != 'X')) return false;
    const char *cursor = text + 2;
    unsigned long result = 0;
    bool any = false;
    for (;;) {
        unsigned int digit = 0;
        if (*cursor >= '0' && *cursor <= '9')
            digit = static_cast<unsigned int>(*cursor - '0');
        else if (*cursor >= 'a' && *cursor <= 'f')
            digit = static_cast<unsigned int>(*cursor - 'a') + 10U;
        else if (*cursor >= 'A' && *cursor <= 'F')
            digit = static_cast<unsigned int>(*cursor - 'A') + 10U;
        else
            break;
        result = result * 16UL + digit;
        any = true;
        ++cursor;
    }
    if (!any) return false;
    value = result;
    return true;
}

bool scan_decimal(const char *text, unsigned long &value)
{
    if (!text || *text < '0' || *text > '9') return false;
    unsigned long result = 0;
    const char *cursor = text;
    while (*cursor >= '0' && *cursor <= '9') {
        result = result * 10UL + static_cast<unsigned long>(*cursor - '0');
        ++cursor;
    }
    value = result;
    return true;
}

/* Finds "key=" inside a "key=value key2=value2" reply and parses the value. */
bool scan_key_hex(const char *text, const char *key, unsigned long &value)
{
    const unsigned long text_length = ghost_length(text, RTGUM_DAEMON_REPLY_CAPACITY);
    const unsigned long key_length = ghost_length(key, 32);
    for (unsigned long index = 0; index + key_length + 2UL <= text_length; ++index) {
        if ((index == 0UL || text[index - 1UL] == ' ') &&
            ghost_starts_with(text + index, key) && text[index + key_length] == '=')
            return scan_hex(text + index + key_length + 1UL, value);
    }
    return false;
}

bool scan_key_decimal(const char *text, const char *key, unsigned long &value)
{
    const unsigned long text_length = ghost_length(text, RTGUM_DAEMON_REPLY_CAPACITY);
    const unsigned long key_length = ghost_length(key, 32);
    for (unsigned long index = 0; index + key_length + 2UL <= text_length; ++index) {
        if ((index == 0UL || text[index - 1UL] == ' ') &&
            ghost_starts_with(text + index, key) && text[index + key_length] == '=')
            return scan_decimal(text + index + key_length + 1UL, value);
    }
    return false;
}

/* Generic ghost-image loader shared by user modules and the mako backend. */

long api_module_load(const char *path,
                     unsigned long *out_base,
                     unsigned long *out_entry,
                     unsigned long *out_size)
{
    return load_ghost_image(path, "ghostEntry", out_base, out_entry, out_size);
}

long load_ghost_image(const char *path,
                      const char *export_name,
                      unsigned long *out_base,
                      unsigned long *out_entry,
                      unsigned long *out_size)
{
    if (!path || !export_name || !out_base || !out_entry || !out_size) return -1;
    /* `path` may point into RTGUM_CTX_PAYLOAD.  Every linker reply reuses that
     * payload, so retain the identity before the first syscall. */
    char registered_path[160];
    unsigned long registered_length = ghost_length(path, sizeof(registered_path));
    if (registered_length == 0UL || registered_length >= sizeof(registered_path))
        return RTGUM_HOST_ERR_INVAL;
    for (unsigned long index = 0; index <= registered_length; ++index)
        registered_path[index] = path[index];
    long status = daemon_syscall(RTGUM_DAEMON_OP_MODULE_LINK,
                                 reinterpret_cast<unsigned long>(path));
    if (status != 0) return status;

    const char *reply = ctx_reply();
    unsigned long base = 0;
    unsigned long size = 0;
    unsigned long needed = 0;
    unsigned long imports = 0;
    unsigned long ifuncs = 0;
    if (!scan_key_hex(reply, "base", base) || !scan_key_decimal(reply, "size", size) ||
        !scan_key_decimal(reply, "needed", needed) ||
        !scan_key_decimal(reply, "imports", imports) ||
        !scan_key_decimal(reply, "ifuncs", ifuncs) || base == 0 || size == 0) {
        if (base != 0) api_module_unload(base);
        return -3001;
    }
    auto rollback = [&](long error) {
        api_module_unload(base);
        return error;
    };

    if (needed != 0UL || imports != 0UL) {
        /* Stage a /proc/self/maps snapshot in a ghost buffer and let the KPM
         * resolve NEEDED libraries and imports from it. /proc maps is a
         * seq_file: a concurrent dlopen can duplicate an already emitted VMA
         * between read chunks. The KPM reports an identical path/base
         * duplicate as AGAIN, which is safe to retry because no registration
         * or relocation has been committed at that point. */
        constexpr long maps_capacity = 512L * 1024L;
        constexpr unsigned int maps_attempt_limit = 4U;
        long remaining = RTGUM_HOST_ERR_AGAIN;
        for (unsigned int maps_attempt = 0; maps_attempt < maps_attempt_limit;
             ++maps_attempt) {
            unsigned long maps_address = 0;
            long allocation = api_ghost_alloc(
                static_cast<unsigned long>(maps_capacity), 3 /* Read | Write */,
                &maps_address);
            if (allocation != 0) return rollback(allocation);
            const long descriptor = user_syscall(
                56, -100, reinterpret_cast<long>("/proc/self/maps"), 0x80000);
            if (descriptor < 0) {
                api_ghost_free(maps_address);
                return rollback(descriptor);
            }
            long total = 0;
            bool complete = false;
            for (;;) {
                const long chunk = user_syscall(
                    63, descriptor, static_cast<long>(maps_address + total),
                    maps_capacity - 1L - total);
                if (chunk < 0) break;
                if (chunk == 0) {
                    complete = true;
                    break;
                }
                total += chunk;
                if (total == maps_capacity - 1L) {
                    unsigned char extra = 0;
                    complete = user_syscall(
                        63, descriptor, reinterpret_cast<long>(&extra), 1L) == 0L;
                    break;
                }
            }
            user_syscall(57, descriptor, 0, 0);
            if (total <= 0 || !complete ||
                *reinterpret_cast<volatile unsigned char *>(maps_address + total - 1L) != '\n') {
                api_ghost_free(maps_address);
                return rollback(-3010); /* incomplete or exceeds fixed buffer */
            }
            *reinterpret_cast<volatile unsigned char *>(maps_address + total) = 0;
            *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) = base;
            *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) =
                maps_address;
            *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 16UL) =
                static_cast<unsigned long>(total);
            remaining = daemon_syscall(RTGUM_DAEMON_OP_MODULE_RESOLVE, 0);
            const long free_status = api_ghost_free(maps_address);
            if (free_status != 0) return rollback(free_status);
            if (remaining != RTGUM_HOST_ERR_AGAIN ||
                maps_attempt + 1U == maps_attempt_limit)
                break;
            api_log("rtgum-stage2-daemon: torn maps snapshot retry");
            (void)host_sleep_ms(2U);
        }
        if (remaining < 0) return rollback(remaining);
        ifuncs = static_cast<unsigned long>(remaining);
    }
    while (ifuncs != 0UL) {
        status = daemon_syscall(RTGUM_DAEMON_OP_MODULE_IFUNC_NEXT, base);
        if (status != 0) return rollback(status);
        reply = ctx_reply();
        unsigned long token = 0;
        unsigned long resolver = 0;
        if (!scan_key_decimal(reply, "token", token) ||
            !scan_key_hex(reply, "resolver", resolver) || token == 0UL || resolver == 0UL)
            return rollback(-3002);

        /* Android's arm64 provider IFUNC ABI is not the ordinary no-argument
         * GNU resolver ABI.  Bionic passes x0 = AT_HWCAP | _IFUNC_ARG_HWCAP
         * and x1 = &{size, AT_HWCAP, AT_HWCAP2}.  Calling a libc resolver
         * without these values can select an unsupported implementation (for
         * example __memmove_aarch64_mops on a CPU without FEAT_MOPS), which
         * then fails with SIGILL on its first instruction.  The KPM wrote the
         * process' real auxv values into the bootstrap context and used the
         * same layout for the daemon's initial fixups; reuse that canonical
         * data for lazily linked backend images.  Image-local no-argument
         * resolvers safely ignore the two extra AArch64 argument registers. */
        struct AndroidIfuncArg final {
            unsigned long size;
            unsigned long hwcap;
            unsigned long hwcap2;
        } ifunc_arg{};
        const auto *saved_ifunc = reinterpret_cast<const volatile unsigned long *>(
            g_ctx_va + RTGUM_CTX_IFUNC_ARG);
        ifunc_arg.size = saved_ifunc[0];
        ifunc_arg.hwcap = saved_ifunc[1];
        ifunc_arg.hwcap2 = saved_ifunc[2];
        const unsigned long first_argument = saved_ifunc[3];
        if (ifunc_arg.size != sizeof(AndroidIfuncArg) ||
            first_argument != (ifunc_arg.hwcap | (1UL << 62U)))
            return rollback(-3004);
        using AndroidIfuncResolver = void *(*)(unsigned long,
                                                const AndroidIfuncArg *);
        const unsigned long target = reinterpret_cast<unsigned long>(
            reinterpret_cast<AndroidIfuncResolver>(resolver)(first_argument,
                                                              &ifunc_arg));
        if (target == 0UL) return rollback(-3005);

        /* {token, target} is passed to the KPM through the ctx payload. */
        *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD) = token;
        *reinterpret_cast<volatile unsigned long *>(g_ctx_va + RTGUM_CTX_PAYLOAD + 8UL) = target;
        const long remaining = daemon_syscall(RTGUM_DAEMON_OP_MODULE_IFUNC_COMMIT, base);
        if (remaining < 0) return rollback(remaining);
        ifuncs = static_cast<unsigned long>(remaining);
    }

    /* Resolve the entry export by name through the ctx payload. The op
     * returns 0 and writes the address back into the payload. */
    const unsigned long name_length = ghost_length(export_name, 128);
    for (unsigned long index = 0; index < name_length; ++index)
        *reinterpret_cast<volatile char *>(g_ctx_va + RTGUM_CTX_PAYLOAD + index) =
            export_name[index];
    *reinterpret_cast<volatile char *>(g_ctx_va + RTGUM_CTX_PAYLOAD + name_length) = '\0';
    const long entry_status = daemon_syscall(RTGUM_DAEMON_OP_MODULE_SYMBOL, base);
    if (entry_status != 0) return rollback(entry_status);
    const unsigned long entry = load_u64(reinterpret_cast<const void *>(
        g_ctx_va + RTGUM_CTX_PAYLOAD));
    if (entry == 0) return rollback(-3003);
    /* A loaded backend can install fork-propagating Shadow Code patches whose
     * branch targets live inside this image.  Publish linker metadata and all
     * backing ghost chunks as one propagation unit before exposing the entry
     * to the caller; inheriting only the patch would leave a child branching
     * into an unmapped VMA-less address. */
    const long fork_policy = api_module_fork_policy(base, true);
    if (fork_policy != 0) return rollback(fork_policy);
    const long registered =
        g_symbol_resolver.RegisterGhost(registered_path, base, size);
    if (registered != 0) return rollback(registered);
    *out_base = base;
    *out_entry = entry;
    *out_size = size;
    return 0;
}

void build_api(unsigned char *ctx)
{
    memset(&g_api, 0, sizeof(g_api));
    g_api.version = RTGUM_GHOST_API_VERSION;
    g_api.reserved = 0;
    g_api.log = api_log;
    g_api.cmdline = api_cmdline;
    g_api.status = api_status;
    g_api.module_load = api_module_load;
    g_api.module_unload = api_module_unload;
    g_api.ghost_alloc = api_ghost_alloc;
    g_api.ghost_protect = api_ghost_protect;
    g_api.ghost_free = api_ghost_free;
    g_api.exit = api_exit;
    g_symbol_resolver.Reset();
    g_symbol_resolver.ops().vma_snapshot = resolver_vma_snapshot;
    g_symbol_resolver.ops().memory_read = resolver_memory_read;
    g_symbol_resolver.ops().ghost_file_size = resolver_ghost_file_size;
    g_symbol_resolver.ops().ghost_file_copy = resolver_ghost_file_copy;
    g_symbol_resolver.ops().open_read = host_open_read;
    g_symbol_resolver.ops().read = host_read;
    g_symbol_resolver.ops().seek = host_seek;
    g_symbol_resolver.ops().close = host_close;
    g_symbol_resolver.ops().map_rw = resolver_map_rw;
    g_symbol_resolver.ops().unmap = host_munmap;
    g_symbol_resolver.ops().allocate_cache = resolver_cache_alloc;
    g_symbol_resolver.ops().release_cache = resolver_cache_free;
    g_engine.Reset();
    g_engine.ops.open_read = host_open_read;
    g_engine.ops.read = host_read;
    g_engine.ops.close = host_close;
    g_engine.ops.mmap = host_mmap;
    g_engine.ops.mprotect = host_mprotect;
    g_engine.ops.munmap = host_munmap;
    g_engine.ops.clear_cache = host_clear_cache;
    g_engine.ops.clone = host_clone;
    g_engine.ops.sleep_ms = host_sleep_ms;
    g_engine.ops.find_export = resolver_find_export;
    g_shadow_engine.Reset();
    g_shadow_engine.ops.read_original = resolver_memory_read;
    g_shadow_engine.ops.ghost_alloc = api_ghost_alloc;
    g_shadow_engine.ops.ghost_protect = api_ghost_protect;
    g_shadow_engine.ops.ghost_free = api_ghost_free;
    g_shadow_engine.ops.patch = shadow_kernel_patch;
    g_shadow_engine.ops.unpatch = shadow_kernel_unpatch;
    g_shadow_engine.ops.query = shadow_kernel_query;
    memset(&g_host_api, 0, sizeof(g_host_api));
    g_host_api.version = RTGUM_HOST_API_V2_VERSION;
    g_host_api.size = sizeof(HostApiV2);
    g_host_api.capabilities = RTGUM_HOST_CAP_FIND_EXPORT | RTGUM_HOST_CAP_NATIVE_REPLACE |
                              RTGUM_HOST_CAP_DEFER | RTGUM_HOST_CAP_JAVA_HOOK |
                              RTGUM_HOST_CAP_NATIVE_SYMBOL | RTGUM_HOST_CAP_WAIT_EXPORT |
                              RTGUM_HOST_CAP_LOAD_DEX | RTGUM_HOST_CAP_LUA |
                              RTGUM_HOST_CAP_LUA_ASYNC |
                              RTGUM_HOST_CAP_BINDER | RTGUM_HOST_CAP_GTRACE |
                              RTGUM_HOST_CAP_ART_MAKO | RTGUM_HOST_CAP_GUM |
                              RTGUM_HOST_CAP_DBI_STALKER_BTI_CHECKED |
                              RTGUM_HOST_CAP_ART_METHOD_FLAGS |
                              RTGUM_HOST_CAP_SYMBOL_RESOLVER |
                              RTGUM_HOST_CAP_LOG |
                              RTGUM_HOST_CAP_BINDER_INTERCEPTOR |
                              RTGUM_HOST_CAP_LINKER_INTERCEPTOR |
                              RTGUM_HOST_CAP_SO_LIFECYCLE |
                              RTGUM_HOST_CAP_JNI_TRACE |
                               RTGUM_HOST_CAP_GTRACE_RUNTIME |
                               RTGUM_HOST_CAP_MULTI_TRACE |
                              RTGUM_HOST_CAP_SHADOW_PAGE;
    g_host_api.find_export = host_find_export;
    g_host_api.hook_native_replace = host_replace;
    g_host_api.hook_native_revert = host_revert;
    g_host_api.hook_query = host_query;
    g_host_api.defer = host_defer;
    g_host_api.sleep_ms = host_sleep_ms;
    g_host_api.hook_java_replace = host_java_replace;
    g_host_api.hook_java_revert = host_java_revert;
    g_host_api.hook_java_method = host_java_method;
    g_host_api.hook_native_symbol = host_hook_symbol;
    g_host_api.wait_export = host_wait_export;
    g_host_api.load_dex = host_load_dex;
    g_host_api.find_class_from_dex = host_find_class_from_dex;
    g_host_api.unload_dex = host_unload_dex;
    g_host_api.lua_eval = host_lua_eval;
    g_host_api.lua_stop = host_lua_stop;
    g_host_api.hook_binder = host_hook_binder;
    g_host_api.gtrace_decode = host_gtrace_decode;
    g_host_api.shadow_replace = host_shadow_replace;
    g_host_api.art_hook_method = host_art_hook_method;
    g_host_api.art_hook_reflected = host_art_hook_reflected;
    g_host_api.art_hook_revert = host_art_hook_revert;
    g_host_api.art_hook_status = host_art_hook_status;
    g_host_api.art_hook_activity_create = host_art_hook_activity_create;
    g_host_api.gum_find_export = host_gum_find_export;
    g_host_api.gum_intercept_attach = host_gum_intercept_attach;
    g_host_api.gum_intercept_attach_address = host_gum_intercept_attach_address;
    g_host_api.gum_intercept_revert = host_gum_intercept_revert;
    g_host_api.gum_replace = host_gum_replace;
    g_host_api.gum_memory_read = host_gum_memory_read;
    g_host_api.gum_memory_write = host_gum_memory_write;
    g_host_api.gum_memory_alloc = host_gum_memory_alloc;
    g_host_api.gum_memory_free = host_gum_memory_free;
    g_host_api.dbi_stalker_start = host_dbi_stalker_start;
    g_host_api.dbi_stalker_invalidate = host_dbi_stalker_invalidate;
    g_host_api.dbi_stalker_stop = host_dbi_stalker_stop;
    g_host_api.art_hook_method_ex = host_art_hook_method_ex;
    g_host_api.symbolize_pc = host_symbolize_pc;
    g_host_api.symbolize_batch = host_symbolize_batch;
    g_host_api.log = api_log;
    g_host_api.binder_interceptor_register = host_binder_interceptor_register;
    g_host_api.linker_interceptor_register = host_linker_interceptor_register;
    g_host_api.interceptor_unregister = host_interceptor_unregister;
    g_host_api.binder_interceptor_set_logging =
        host_binder_interceptor_set_logging;
    g_host_api.interceptor_query = host_interceptor_query;
    g_host_api.so_lifecycle_register = host_so_lifecycle_register;
    g_host_api.jni_trace_register = host_jni_trace_register;
    g_host_api.gtrace_format_path = host_gtrace_format_path;
    g_host_api.trace_start = host_trace_start;
    g_host_api.trace_stop = host_trace_stop;
    g_host_api.trace_query = host_trace_query;
    g_host_api.lua_eval_async = host_lua_eval_async;
    g_api.host = &g_host_api;
    g_api_ready = true;
    *reinterpret_cast<volatile unsigned long *>(ctx + RTGUM_CTX_API) =
        reinterpret_cast<unsigned long>(&g_api);
}

void set_error(long code)
{
    api_status(RTGUM_DAEMON_STATUS_EXTRA, static_cast<unsigned long>(code));
}

} // namespace

extern "C" void *rtgum_stage2_daemon_ifunc_impl()
{
    return reinterpret_cast<void *>(RTGUM_DAEMON_IFUNC_MAGIC);
}

extern "C" void *rtgum_stage2_daemon_ifunc_resolver()
{
    return reinterpret_cast<void *>(rtgum_stage2_daemon_ifunc_impl);
}

extern "C" void *rtgum_stage2_daemon_ifunc_probe(void)
    __attribute__((ifunc("rtgum_stage2_daemon_ifunc_resolver"), visibility("default")));

extern "C" __attribute__((visibility("default"), aligned(4096), used))
unsigned char rtgum_stage2_daemon_ctx[RTGUM_CTX_SIZE] = {};

extern "C" __attribute__((visibility("default"), aligned(4096), used))
unsigned char rtgum_stage2_daemon_trampoline[4096] = {};

extern "C" __attribute__((visibility("default")))
unsigned long rtgum_stage2_daemon_status[8] = {};

namespace {

struct DaemonDescriptor final {
    unsigned long magic;
    unsigned int abi;
    unsigned int state;
};

DaemonDescriptor descriptor{0x525447554d443253UL, 1U, 0U};

} // namespace

extern "C" __attribute__((visibility("default"))) const void *
rtgum_stage2_daemon_descriptor = &descriptor;

extern "C" __attribute__((visibility("default"), noinline)) unsigned long
rtgum_stage2_daemon_entry()
{
    return RTGUM_DAEMON_MAGIC;
}

extern "C" __attribute__((visibility("default"), noinline)) unsigned long
rtgum_stage2_daemon_dispatch(void *raw_ctx)
{
    auto *ctx = static_cast<unsigned char *>(raw_ctx);
    if (!ctx) return 1;
    const unsigned long cmd = load_u64(ctx + RTGUM_CTX_CMD);
    if (!g_api_ready) {
        g_ctx_va = reinterpret_cast<unsigned long>(ctx);
        for (unsigned int index = 0; index < 4U; ++index)
            g_session_words[index] = load_u64(ctx + RTGUM_CTX_SESSION + index * 8UL);
        g_status_va = load_u64(ctx + RTGUM_CTX_STATUS);
        build_api(ctx);
        api_log("build-api-done");
    }
    api_log("dispatch-enter");

    switch (cmd) {
    case RTGUM_DAEMON_CMD_INIT: {
        if (rtgum_stage2_daemon_ifunc_probe() !=
            reinterpret_cast<void *>(RTGUM_DAEMON_IFUNC_MAGIC)) {
            set_error(-4101);
            api_status(RTGUM_DAEMON_STATUS_MAGIC, 0);
            break;
        }
        api_status(RTGUM_DAEMON_STATUS_PHASE, RTGUM_DAEMON_PHASE_INIT);
        api_status(RTGUM_DAEMON_STATUS_MAGIC, RTGUM_DAEMON_MAGIC);
        api_log(prepare_mako_reflection_cache()
                    ? "rtgum-stage2-daemon: pre-fork reflection cache ready"
                    : "rtgum-stage2-daemon: pre-fork reflection cache unavailable");
        api_log(prepare_dex_jni_cache()
                    ? "rtgum-stage2-daemon: pre-fork dex cache ready"
                    : "rtgum-stage2-daemon: pre-fork dex cache deferred");
        api_log("rtgum-stage2-daemon: init");
        break;
    }
    case RTGUM_DAEMON_CMD_FORK_CHILD: {
        /* A lock word and app-specific JNI references must never be inherited
         * as live ownership. Bootstrap/framework method IDs in g_dex_jni are
         * Zygote-safe and intentionally remain cached; no global class refs
         * are retained in the parent. DEX load itself is rejected before
         * PACKAGE, so there can be no parent slots to clone here. */
        __atomic_store_n(&g_dex_lock, 0U, __ATOMIC_RELEASE);
        memset(g_dex_slots, 0, sizeof(g_dex_slots));
        g_dex_app_loader = nullptr;
        g_dex_process_ready = false;
        api_status(RTGUM_DAEMON_STATUS_PHASE, RTGUM_DAEMON_PHASE_FORK);
        api_status(RTGUM_DAEMON_STATUS_MAGIC, RTGUM_DAEMON_MAGIC);
        break;
    }
    case RTGUM_DAEMON_CMD_PACKAGE: {
        const char *package = reinterpret_cast<const char *>(ctx + RTGUM_CTX_PAYLOAD);
        const unsigned long package_length = ghost_length(package, 64);
        const char *path = package + package_length + 1UL;
        api_log("package-case");
        if (package_length == 0UL || *path == '\0') {
            set_error(-4001);
            break;
        }
        /* Enables DEX calls only in a selected application process. The app
         * parent is captured lazily because this first package dispatch can
         * precede Application creation. */
        g_dex_process_ready = true;
        g_symbol_resolver.SetPackage(package);
        /* Optional third payload segment: the mako path selected by the
         * Manager switch. Every PACKAGE command replaces the selection so
         * disabling ART cannot inherit a stale path in the same process. */
        const char *mako = path + ghost_length(path, 160) + 1UL;
        const unsigned long mako_length = ghost_length(mako, 160);
        g_mako_enabled = false;
        g_mako_path[0] = '\0';
        if (mako_length != 0UL) {
            for (unsigned long index = 0; index < mako_length; ++index)
                g_mako_path[index] = mako[index];
            g_mako_path[mako_length] = '\0';
            g_mako_enabled = true;
            api_log("rtgum-stage2-daemon: mako path configured");
        } else {
            api_log("rtgum-stage2-daemon: mako disabled");
        }
        /* Optional fourth/fifth payload segments identify the Gum and Lua
         * blobs cached by KPM at configuration time.  Preserve those exact
         * identities: load_ghost_image uses them as cache keys and never asks
         * the application to open the staging files. */
        const char *gum = mako + mako_length + 1UL;
        const unsigned long gum_length = ghost_length(gum, 160);
        g_gum_path[0] = '\0';
        if (gum_length != 0UL) {
            for (unsigned long index = 0; index < gum_length; ++index)
                g_gum_path[index] = gum[index];
            g_gum_path[gum_length] = '\0';
            api_log("rtgum-stage2-daemon: gum ghost cache configured");
        }
        const char *lua = gum + gum_length + 1UL;
        const unsigned long lua_length = ghost_length(lua, 160);
        g_lua_path[0] = '\0';
        if (lua_length != 0UL) {
            for (unsigned long index = 0; index < lua_length; ++index)
                g_lua_path[index] = lua[index];
            g_lua_path[lua_length] = '\0';
            api_log("rtgum-stage2-daemon: lua ghost cache configured");
        }
        if (g_module_base != 0) break;
        char cmdline[256];
        const long command_length =
            api_cmdline_at(reinterpret_cast<unsigned long>(ctx), cmdline, sizeof(cmdline));
        api_log("cmdline-done");
        if (command_length <= 0) {
            set_error(command_length);
            break;
        }
        if (!ghost_starts_with(cmdline, package)) {
            /* At the first dispatch (DdmSetAppName comm rename) Android has
             * not yet rewritten /proc/<pid>/cmdline: it still holds the
             * zygote's value. The KPM already verified the package via comm,
             * so accept the zygote transitional state. */
            if (!ghost_starts_with(cmdline, "zygote")) {
                api_log("cmdline-mismatch cmd=");
                api_log(cmdline);
                api_log(" pkg=");
                api_log(package);
                set_error(-4003);
                break;
            }
            api_log("cmdline-transitional-zygote");
        }
        unsigned long base = 0;
        unsigned long entry = 0;
        unsigned long size = 0;
        const long result = api_module_load(path, &base, &entry, &size);
        if (result != 0 || base == 0 || entry == 0) {
            set_error(result != 0 ? result : -4003);
            break;
        }
        g_module_base = base;
        g_module_size = size;
        const long unload_entry =
            daemon_syscall(RTGUM_DAEMON_OP_MODULE_UNLOAD_ENTRY, base);
        g_module_unload_entry = unload_entry > 0 ?
            static_cast<unsigned long>(unload_entry) : 0;
        api_status(RTGUM_DAEMON_STATUS_MODULE_BASE, base);
        /* Lua evaluation moves the large Gum load onto its bionic pthread;
         * the small declaration-only module entry can remain synchronous. */
        reinterpret_cast<GhostEntry>(entry)(&g_api);
        api_status(RTGUM_DAEMON_STATUS_MODULES, 1);
        api_status(RTGUM_DAEMON_STATUS_PHASE, RTGUM_DAEMON_PHASE_MODULE);
        api_log("rtgum-stage2-daemon: module loaded");
        break;
    }
    case RTGUM_DAEMON_CMD_RELOAD: {
        /* Clear the old state first (清场), then inject the new module (进场). */
        const long unload_status = release_active_module();
        if (unload_status != 0) {
            set_error(unload_status);
            break;
        }
        api_status(RTGUM_DAEMON_STATUS_EXTRA, 0);
        const char *package = reinterpret_cast<const char *>(ctx + RTGUM_CTX_PAYLOAD);
        const unsigned long package_length = ghost_length(package, 64);
        const char *path = package + package_length + 1UL;
        if (package_length == 0UL || *path == '\0') {
            set_error(-4100);
            break;
        }
        g_symbol_resolver.SetPackage(package);
        unsigned long base = 0;
        unsigned long entry = 0;
        unsigned long size = 0;
        const long result = api_module_load(path, &base, &entry, &size);
        if (result != 0 || base == 0 || entry == 0) {
            set_error(result != 0 ? result : -4101);
            break;
        }
        g_module_base = base;
        g_module_size = size;
        const long unload_entry =
            daemon_syscall(RTGUM_DAEMON_OP_MODULE_UNLOAD_ENTRY, base);
        g_module_unload_entry = unload_entry > 0 ?
            static_cast<unsigned long>(unload_entry) : 0;
        api_status(RTGUM_DAEMON_STATUS_MODULE_BASE, base);
        reinterpret_cast<GhostEntry>(entry)(&g_api);
        api_status(RTGUM_DAEMON_STATUS_MODULES, 1);
        api_status(RTGUM_DAEMON_STATUS_PHASE, RTGUM_DAEMON_PHASE_RELOADED);
        api_log("rtgum-stage2-daemon: module reloaded");
        break;
    }
    case RTGUM_DAEMON_CMD_SHUTDOWN: {
        const long unload_status = release_active_module();
        if (unload_status != 0) {
            set_error(unload_status);
            break;
        }
        /* release_active_module() is a no-op when no .ghm is active. Sweep
         * the registry anyway, then drop the cached app parent so hot daemon
         * teardown does not leave a JNI global reference behind. */
        const long dex_status = release_all_dex_loaders();
        if (dex_status != 0) {
            set_error(dex_status);
            break;
        }
        const long process_status = release_dex_process_state();
        if (process_status != 0) {
            set_error(process_status);
            break;
        }
        const long interceptor_status = release_interceptor_process_state();
        if (interceptor_status != 0) {
            set_error(interceptor_status);
            break;
        }
        api_status(RTGUM_DAEMON_STATUS_PHASE, RTGUM_DAEMON_PHASE_SHUTDOWN);
        api_status(RTGUM_DAEMON_STATUS_MAGIC, 0);
        api_log("rtgum-stage2-daemon: shutdown");
        break;
    }
    default:
        break;
    }
    return 0;
}
